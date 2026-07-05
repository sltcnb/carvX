# CarvX Web

Flask web interface for the carvX carver. Runs the real `carvx` package
from the repo root — no bundled copy — so it always matches the CLI.

## Quick Start

```bash
cd web
python3 -m venv venv
venv/bin/pip install -r requirements.txt
venv/bin/python app/main.py

# open http://127.0.0.1:5050
```

Binds to `127.0.0.1` by default. To expose on the network (only on a
trusted LAN — there is no authentication):

```bash
CARVX_WEB_HOST=0.0.0.0 PORT=8080 venv/bin/python app/main.py
```

## Features

- **Upload disk images** by drag-and-drop (multi-file for split segments:
  `.e01/.e02`, `.001/.002`) or reference an existing path in place (no copy)
- **Modes**: signature carve, NTFS / ext4 / FAT / HFS+ / APFS undelete, auto
- **Live progress**: streamed from carvx `--machine` JSON events
  (percent, MiB/s, ETA, files carved), with cancel
- **BitLocker**: recovery key or password, passed via environment
  (`CARVX_BITLOCKER`), never on the command line
- **Results**: file table with offsets/hashes/confidence, image gallery,
  CSV / HTML report / timeline, per-file or ZIP download

## Storage

Everything lives under `web/data/` (not served statically):

- `data/uploads/<job>/` — uploaded images
- `data/carved/<job>/`  — carve output + manifest
- `data/jobs/<job>.json` — job state (survives restart)

Delete a job (upload + results + state) with `POST /delete/<job_id>`.

## API

- `POST /upload` — upload image file(s) (multipart, field `file`)
- `POST /upload/path` — reference an existing file path (JSON `{path}`)
- `POST /run` — start a job (JSON options)
- `POST /cancel/<job_id>` — cancel a running job (partial results kept)
- `GET /status/<job_id>` — status + live progress
- `GET /results/<job_id>` — results page (`?limit=N`)
- `GET /download/<job_id>/<path>` — download one carved file
- `GET /view/<job_id>/<path>` — inline view (images only)
- `GET /download-manifest/<job_id>` — manifest JSON
- `GET /download-all/<job_id>` — everything as ZIP
- `POST /delete/<job_id>` — remove job data
