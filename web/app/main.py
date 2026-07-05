"""CarvX Web — Flask front-end for the carvx carver.

Runs the real carvx package from the repo root (no bundled copy) via
`python -m carvx --machine` and streams its JSON-lines events into live
job progress. Job state is persisted per job under web/data/jobs/ so a
server restart does not lose history.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from flask import (Flask, abort, jsonify, render_template, request,
                   send_file, send_from_directory)
from werkzeug.utils import secure_filename

WEB_ROOT = Path(__file__).resolve().parent.parent      # web/
REPO_ROOT = WEB_ROOT.parent                            # carvX/ (contains carvx/)
DATA_DIR = WEB_ROOT / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
CARVED_DIR = DATA_DIR / "carved"
JOBS_DIR = DATA_DIR / "jobs"

if not (REPO_ROOT / "carvx" / "__main__.py").exists():
    sys.exit(f"error: carvx package not found at {REPO_ROOT / 'carvx'} — "
             "the web app must live inside the carvX repo (web/)")

for d in (UPLOAD_DIR, CARVED_DIR, JOBS_DIR):
    d.mkdir(parents=True, exist_ok=True)

app = Flask(__name__,
            template_folder=WEB_ROOT / "templates",
            static_folder=WEB_ROOT / "static")
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024 * 1024  # 50 GB

ALLOWED_EXTENSIONS = {"dd", "img", "iso", "e01", "raw", "bin", "aff",
                      "vmdk", "qcow2", "vdi"}
# split segments: image.001/.002…, image.e01/.e02…, image.dd.000…
_SEGMENT_RE = re.compile(r"^(e\d{2}|s\d{2}|\d{3})$", re.IGNORECASE)

MODES = {"carve": None, "ntfs": "--ntfs", "ext4": "--ext4", "fat": "--fat",
         "hfs": "--hfs", "apfs": "--apfs", "auto": "--auto"}

_JOB_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

# live process handles (in-memory only; job metadata lives on disk)
_procs: dict[str, subprocess.Popen] = {}
_lock = threading.Lock()


# ---------------------------------------------------------------- job store

def _job_path(job_id: str) -> Path:
    return JOBS_DIR / f"{job_id}.json"


def _load_job(job_id: str) -> dict | None:
    p = _job_path(job_id)
    if not p.exists():
        return None
    with open(p) as fh:
        return json.load(fh)


def _save_job(job: dict) -> None:
    p = _job_path(job["job_id"])
    tmp = p.with_suffix(".tmp")
    with open(tmp, "w") as fh:
        json.dump(job, fh, indent=2)
    tmp.replace(p)


def _valid_job_id(job_id: str) -> str:
    if not _JOB_ID_RE.match(job_id or ""):
        abort(400, description="invalid job id")
    return job_id


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------- helpers

def allowed_file(filename: str) -> bool:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return ext in ALLOWED_EXTENSIONS or bool(_SEGMENT_RE.match(ext))


def _primary_segment(paths: list[Path]) -> Path:
    """First segment of a (possibly split) image: .e01/.001 before .e02/.002."""
    return sorted(paths, key=lambda p: p.name.lower())[0]


def get_supported_types() -> list[dict]:
    result = subprocess.run(
        [sys.executable, "-m", "carvx", "--list-types"],
        capture_output=True, text=True, cwd=REPO_ROOT, timeout=30)
    types = []
    for line in result.stdout.splitlines()[1:]:          # skip header
        parts = line.split()
        if parts:
            types.append({"name": parts[0],
                          "description": " ".join(parts[1:])})
    return types


# ---------------------------------------------------------------- routes

@app.route("/")
def index():
    return render_template("index.html",
                           job_id=str(uuid.uuid4()),
                           types=get_supported_types())


@app.route("/upload", methods=["POST"])
def upload_file():
    files = [f for f in request.files.getlist("file") if f.filename]
    if not files:
        return jsonify({"error": "No file provided"}), 400
    for f in files:
        if not allowed_file(f.filename):
            return jsonify({"error": f"File type not allowed: {f.filename}. "
                            f"Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))} "
                            "and split segments (.001, .e02, ...)"}), 400

    job_id = _valid_job_id(request.form.get("job_id") or str(uuid.uuid4()))
    job_dir = UPLOAD_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)

    saved = []
    for f in files:
        dest = job_dir / secure_filename(f.filename)
        f.save(dest)
        saved.append(dest)

    primary = _primary_segment(list(job_dir.iterdir()))
    job = _load_job(job_id) or {"job_id": job_id}
    job.update(source=str(primary), status="uploaded",
               files=[p.name for p in job_dir.iterdir()])
    _save_job(job)
    return jsonify({"success": True, "job_id": job_id,
                    "filename": primary.name,
                    "size": sum(p.stat().st_size for p in saved)})


@app.route("/upload/path", methods=["POST"])
def upload_path():
    data = request.get_json(silent=True) or {}
    filepath = data.get("path", "")
    job_id = _valid_job_id(data.get("job_id") or str(uuid.uuid4()))
    if not filepath:
        return jsonify({"error": "No path provided"}), 400

    path = Path(filepath).expanduser()
    if not path.is_file():
        return jsonify({"error": f"Not a readable file: {path}"}), 404
    if not allowed_file(path.name):
        return jsonify({"error": f"File type not allowed. Allowed: "
                        f"{', '.join(sorted(ALLOWED_EXTENSIONS))}"}), 400

    # reference in place — a disk image can be 50 GB, never copy it
    job = _load_job(job_id) or {"job_id": job_id}
    job.update(source=str(path.resolve()), status="uploaded",
               files=[path.name])
    _save_job(job)
    return jsonify({"success": True, "job_id": job_id,
                    "filename": path.name, "size": path.stat().st_size})


def _build_command(data: dict, source: str, output_dir: Path) -> list[str]:
    cmd = [sys.executable, "-m", "carvx", source,
           "-o", str(output_dir), "--machine"]
    mode = data.get("mode", "carve")
    flag = MODES.get(mode)
    if flag:
        cmd.append(flag)
    if mode in ("carve", "auto") and data.get("types"):
        cmd.extend(["-t", ",".join(data["types"])])
    for opt, flag in (("offset", "--offset"), ("length", "--length"),
                      ("align", "--align")):
        val = str(data.get(opt) or "").strip()
        if val and val != "0":
            cmd.extend([flag, val])
    if int(data.get("jobs") or 1) != 1:
        cmd.extend(["-j", str(int(data["jobs"]))])
    if data.get("validate"):
        cmd.append("--validate")
    if data.get("drop_failed"):
        cmd.append("--drop-failed")
    if data.get("dry_run"):
        cmd.append("--dry-run")
    if data.get("csv"):
        cmd.extend(["--csv", str(output_dir / "results.csv")])
    if data.get("html"):
        cmd.extend(["--html", str(output_dir / "report.html")])
    if data.get("timeline"):
        cmd.extend(["--timeline", str(output_dir / "timeline.csv")])
    return cmd


@app.route("/run", methods=["POST"])
def run_carvx():
    data = request.get_json(silent=True) or {}
    job_id = _valid_job_id(data.get("job_id", ""))
    job = _load_job(job_id)
    if job is None or not job.get("source"):
        return jsonify({"error": "No file uploaded for this job"}), 404
    if job.get("status") == "running":
        return jsonify({"error": "Job already running"}), 409
    if not Path(job["source"]).exists():
        return jsonify({"error": f"Source vanished: {job['source']}"}), 410

    output_dir = CARVED_DIR / job_id
    output_dir.mkdir(parents=True, exist_ok=True)
    cmd = _build_command(data, job["source"], output_dir)

    # BitLocker credentials go through the environment (CARVX_BITLOCKER),
    # never through argv, so they are not visible in `ps` or job records.
    env = os.environ.copy()
    creds = {}
    if data.get("bitlocker_recovery_key"):
        creds["recovery"] = data["bitlocker_recovery_key"]
    if data.get("bitlocker_password"):
        creds["password"] = data["bitlocker_password"]
    if creds:
        env["CARVX_BITLOCKER"] = json.dumps(creds)

    job.update(status="running", mode=data.get("mode", "carve"),
               command=" ".join(c for c in cmd), started=_now(),
               finished=None, returncode=None, output="", error="",
               progress=None, carved=0, bitlocker=bool(creds))
    _save_job(job)

    proc = subprocess.Popen(cmd, cwd=REPO_ROOT, env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    with _lock:
        _procs[job_id] = proc

    threading.Thread(target=_watch_job, args=(job_id, proc),
                     daemon=True).start()
    return jsonify({"success": True, "job_id": job_id, "status": "running"})


def _watch_job(job_id: str, proc: subprocess.Popen) -> None:
    """Consume --machine JSON-lines from stdout, persist progress as we go."""
    job = _load_job(job_id)
    stderr_buf = []
    t = threading.Thread(target=lambda: stderr_buf.append(proc.stderr.read()),
                         daemon=True)
    t.start()

    events_tail = []
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            events_tail.append(line)
            continue
        kind = ev.get("event")
        if kind == "progress":
            total = ev.get("total") or 0
            job["progress"] = {
                "done": ev.get("done", 0), "total": total,
                "percent": round(100 * ev.get("done", 0) / total, 1)
                           if total else None,
                "eta_s": ev.get("eta_s"), "rate_mibs": ev.get("rate_mibs"),
            }
            if "carved" in ev:
                job["carved"] = ev["carved"]
        elif kind == "carve":
            job["carved"] = job.get("carved", 0) + 1
        elif kind == "summary":
            job["summary"] = {k: v for k, v in ev.items() if k != "event"}
        _save_job(job)

    proc.wait()
    t.join(timeout=10)
    canceled = job_id in _canceled
    _canceled.discard(job_id)
    job["returncode"] = proc.returncode
    job["error"] = (stderr_buf[0] if stderr_buf else "")[-20000:]
    job["output"] = "\n".join(events_tail)[-20000:]
    job["finished"] = _now()
    if canceled:
        job["status"] = "canceled"
    else:
        job["status"] = "completed" if proc.returncode == 0 else "failed"
    if not job.get("carved"):
        # fs-undelete modes don't emit per-file events; count the output
        job["carved"] = len(_collect_files(CARVED_DIR / job_id))
    if job.get("progress") and job["status"] == "completed":
        job["progress"]["percent"] = 100.0
    _save_job(job)
    with _lock:
        _procs.pop(job_id, None)


_canceled: set[str] = set()


@app.route("/cancel/<job_id>", methods=["POST"])
def cancel_job(job_id):
    _valid_job_id(job_id)
    with _lock:
        proc = _procs.get(job_id)
    if proc is None or proc.poll() is not None:
        return jsonify({"error": "Job not running"}), 409
    _canceled.add(job_id)
    proc.terminate()
    return jsonify({"success": True, "status": "canceling"})


@app.route("/status/<job_id>")
def job_status(job_id):
    _valid_job_id(job_id)
    job = _load_job(job_id)
    if job is None:
        return jsonify({"error": "Job not found"}), 404
    result = {k: job.get(k) for k in
              ("job_id", "status", "started", "finished", "progress",
               "carved", "summary", "mode")}
    if job.get("status") in ("completed", "failed", "canceled"):
        result["output"] = job.get("output", "")
        result["error"] = job.get("error", "")
        result["returncode"] = job.get("returncode")
    return jsonify(result)


def _collect_files(output_dir: Path) -> list[dict]:
    """Carved files on disk, enriched from any manifest.json found."""
    meta = {}
    for mf in output_dir.rglob("manifest.json"):
        try:
            manifest = json.loads(mf.read_text())
        except ValueError:
            continue
        base = mf.parent
        for rec in manifest.get("files", []):
            if rec.get("path"):
                p = (base / rec["path"]).resolve()
                meta[str(p)] = rec

    files = []
    skip = {"manifest.json", "results.csv", "report.html", "timeline.csv"}
    for f in sorted(output_dir.rglob("*")):
        if not f.is_file() or f.name in skip:
            continue
        rel = f.relative_to(output_dir)
        rec = meta.get(str(f.resolve()), {})
        files.append({
            "path": str(rel), "name": f.name, "size": f.stat().st_size,
            "ext": (rec.get("ext") or f.suffix.lstrip(".") or "?").lower(),
            "offset": rec.get("offset"), "sha256": rec.get("sha256", ""),
            "confidence": rec.get("confidence", ""),
            "validated": rec.get("validated", False),
        })
    return files


@app.route("/results/<job_id>")
def results(job_id):
    _valid_job_id(job_id)
    output_dir = CARVED_DIR / job_id
    if not output_dir.exists():
        abort(404, description="No results found")

    manifest = None
    mf = output_dir / "manifest.json"
    if mf.exists():
        try:
            manifest = json.loads(mf.read_text())
        except ValueError:
            pass

    files = _collect_files(output_dir)
    limit = min(int(request.args.get("limit", 200)), 2000)
    reports = [n for n in ("report.html", "results.csv", "timeline.csv")
               if (output_dir / n).exists()]
    return render_template("results.html", job_id=job_id, manifest=manifest,
                           files=files[:limit], total_files=len(files),
                           reports=reports)


_INLINE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico"}


@app.route("/download/<job_id>/<path:filename>")
def download_file(job_id, filename):
    _valid_job_id(job_id)
    # send_from_directory refuses paths that escape output_dir
    return send_from_directory(CARVED_DIR / job_id, filename,
                               as_attachment=True)


@app.route("/view/<job_id>/<path:filename>")
def view_file(job_id, filename):
    """Inline display, images only — carved HTML/SVG must never render
    from this origin."""
    _valid_job_id(job_id)
    if Path(filename).suffix.lower() not in _INLINE_EXTS:
        abort(403, description="Inline view is limited to images")
    return send_from_directory(CARVED_DIR / job_id, filename)


@app.route("/download-manifest/<job_id>")
def download_manifest(job_id):
    _valid_job_id(job_id)
    return send_from_directory(CARVED_DIR / job_id, "manifest.json",
                               as_attachment=True)


@app.route("/download-all/<job_id>")
def download_all(job_id):
    _valid_job_id(job_id)
    output_dir = CARVED_DIR / job_id
    if not output_dir.exists():
        abort(404, description="Results not found")

    # zip to a temp file (results can be many GB — never buffer in RAM),
    # unlink immediately and stream from the open handle
    fd, tmp = tempfile.mkstemp(suffix=".zip", dir=DATA_DIR)
    try:
        with os.fdopen(fd, "wb") as raw, \
                zipfile.ZipFile(raw, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in output_dir.rglob("*"):
                if f.is_file():
                    zf.write(f, f.relative_to(output_dir))
        fh = open(tmp, "rb")
    finally:
        os.unlink(tmp)
    return send_file(fh, mimetype="application/zip", as_attachment=True,
                     download_name=f"carvx_{job_id}.zip")


@app.route("/delete/<job_id>", methods=["POST", "DELETE"])
def delete_job(job_id):
    _valid_job_id(job_id)
    with _lock:
        if job_id in _procs and _procs[job_id].poll() is None:
            return jsonify({"error": "Job is running — cancel it first"}), 409
    import shutil
    for p in (UPLOAD_DIR / job_id, CARVED_DIR / job_id):
        shutil.rmtree(p, ignore_errors=True)
    _job_path(job_id).unlink(missing_ok=True)
    return jsonify({"success": True})


if __name__ == "__main__":
    host = os.environ.get("CARVX_WEB_HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 5050))
    debug = os.environ.get("CARVX_WEB_DEBUG") == "1"
    app.run(host=host, port=port, debug=debug, threaded=True)
