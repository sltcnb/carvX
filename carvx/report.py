"""Post-processing of a carvx manifest: timeline + HTML report.

Both read a manifest.json produced by any mode and write a derived artifact.
Kept separate from the scan so they can be re-run on an existing manifest.
"""

import datetime
import html
import json
import os


def _iso(ts: int) -> str:
    if not ts:
        return ""
    try:
        return datetime.datetime.fromtimestamp(
            ts, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return ""


def build_timeline(manifest: dict) -> list[dict]:
    """Flatten file timestamps into sorted (time, macb, name, ...) events.

    Each timestamp kind (m/a/c/b/crtime/dtime) becomes its own event row, the
    way mactime/plaso present a super-timeline.
    """
    KINDS = [("mtime", "m..."), ("atime", ".a.."), ("ctime", "..c."),
             ("crtime", "...b"), ("dtime", "dtime")]
    events = []
    for f in manifest.get("files", []):
        ts = f.get("timestamps") or {}
        name = f.get("name") or f.get("path") or f"offset_{f.get('offset', 0):#x}"
        for key, macb in KINDS:
            t = ts.get(key)
            if t:
                events.append({
                    "time": int(t), "iso": _iso(int(t)), "macb": macb,
                    "name": name, "size": f.get("size", 0),
                    "deleted": f.get("deleted", True),
                    "sha256": f.get("sha256", ""), "ext": f.get("ext", ""),
                })
    events.sort(key=lambda e: e["time"])
    return events


def write_timeline_csv(manifest: dict, path: str) -> int:
    import csv
    events = build_timeline(manifest)
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["iso", "time", "macb", "name", "size",
                                           "ext", "deleted", "sha256"])
        w.writeheader()
        w.writerows(events)
    return len(events)


def write_timeline_jsonl(manifest: dict, path: str) -> int:
    events = build_timeline(manifest)
    with open(path, "w") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")
    return len(events)


_IMAGE_EXTS = {"jpg", "jpeg", "png", "gif", "bmp", "webp", "ico", "heic", "tif"}


def write_html_report(manifest: dict, path: str, out_root: str = "") -> int:
    """Self-contained HTML report: summary, table, thumbnail gallery of images.

    Thumbnails reference carved files by relative path (no copying), so open the
    report from inside the output directory.
    """
    files = manifest.get("files", [])
    from collections import Counter
    by_ext = Counter(f.get("ext", "?") for f in files)
    total = sum(f.get("size", 0) for f in files)
    report_dir = os.path.dirname(os.path.abspath(path))

    def rel(p):
        if not p:
            return ""
        try:
            return os.path.relpath(p, report_dir)
        except ValueError:
            return p

    rows = []
    for f in files:
        conf = f.get("confidence", "high" if f.get("validated") else "low")
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(f.get('ext', '')))}</td>"
            f"<td class=num>{f.get('size', 0):,}</td>"
            f"<td class=mono>{f.get('offset', 0)}</td>"
            f"<td class='conf {html.escape(conf)}'>{html.escape(conf)}</td>"
            f"<td class=mono>{html.escape((f.get('sha256') or '')[:16])}</td>"
            f"<td>{html.escape(f.get('name') or rel(f.get('path', '')))}</td>"
            "</tr>")

    gallery = []
    for f in files:
        if f.get("ext", "").lower() in _IMAGE_EXTS and f.get("path"):
            src = html.escape(rel(f["path"]))
            cap = html.escape(f.get("name") or os.path.basename(f["path"]))
            gallery.append(
                f"<figure><img loading=lazy src='{src}'>"
                f"<figcaption>{cap}<br>{f.get('size', 0):,} B</figcaption></figure>")

    cards = "".join(f"<span class=chip>{html.escape(e)} <b>{n}</b></span>"
                    for e, n in by_ext.most_common())
    doc = f"""<!doctype html><html><head><meta charset=utf-8>
<title>carvX report</title>
<style>
 body{{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#222;background:#fafafa}}
 h1{{margin:0 0 .25rem}} .sub{{color:#666;margin-bottom:1rem}}
 .chip{{display:inline-block;background:#eef;border-radius:1rem;padding:.2rem .7rem;margin:.15rem}}
 table{{border-collapse:collapse;width:100%;background:#fff;margin:1rem 0}}
 th,td{{padding:.35rem .6rem;border-bottom:1px solid #eee;text-align:left}}
 th{{background:#f4f4f8;position:sticky;top:0}}
 .num{{text-align:right;font-variant-numeric:tabular-nums}}
 .mono{{font-family:ui-monospace,monospace;font-size:12px;color:#555}}
 .conf.low,.conf.failed{{color:#b00}} .conf.verified{{color:#080}}
 .gallery{{display:flex;flex-wrap:wrap;gap:.75rem}}
 figure{{margin:0;width:140px;background:#fff;border:1px solid #eee;padding:.4rem;border-radius:6px}}
 figure img{{width:100%;height:100px;object-fit:contain;background:#f0f0f0}}
 figcaption{{font-size:11px;color:#555;word-break:break-all;margin-top:.3rem}}
</style></head><body>
<h1>carvX recovery report</h1>
<div class=sub>{html.escape(manifest.get('tool', 'carvx'))} &middot;
 source {html.escape(str(manifest.get('source', '')))} &middot;
 {len(files):,} files &middot; {total / (1 << 20):,.1f} MiB</div>
<div>{cards}</div>
<h2>Files</h2>
<table><thead><tr><th>ext<th>size<th>offset<th>confidence<th>sha256<th>name</tr></thead>
<tbody>{''.join(rows)}</tbody></table>
{'<h2>Images (' + str(len(gallery)) + ')</h2><div class=gallery>' + ''.join(gallery) + '</div>' if gallery else ''}
</body></html>"""
    with open(path, "w") as fh:
        fh.write(doc)
    return len(files)


def run_report(args) -> int:
    """CLI: derive timeline/HTML from an existing manifest (or one just written)."""
    import sys
    manifest_path = args.from_manifest or os.path.join(args.output, "manifest.json")
    try:
        with open(manifest_path) as fh:
            manifest = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        print(f"error: cannot read manifest {manifest_path}: {e}", file=sys.stderr)
        return 1

    did = False
    if args.timeline:
        n = (write_timeline_jsonl if args.timeline.endswith(".jsonl")
             else write_timeline_csv)(manifest, args.timeline)
        print(f"timeline: {n} events -> {args.timeline}", file=sys.stderr)
        did = True
    if args.html:
        n = write_html_report(manifest, args.html)
        print(f"html report: {n} files -> {args.html}", file=sys.stderr)
        did = True
    if not did:
        print("nothing to do: pass --timeline FILE and/or --html FILE",
              file=sys.stderr)
        return 2
    return 0
