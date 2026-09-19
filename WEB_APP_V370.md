# V3.70 Local Web Application

Security Platform now includes a local browser UI backed by the existing Python engine.

## Run

```bash
python run_web.py
```

Open `http://127.0.0.1:8000` in a browser.

API documentation is available locally at `/api/docs`.

## Architecture

Browser UI -> FastAPI local API -> PentestEngine -> governed specialist/AI layers -> evidence.

The web UI does not create a second execution engine. It calls the existing named engine capabilities and keeps authorization/scope checks in the backend.

## Security boundary

- Localhost by default.
- No arbitrary shell endpoint.
- Active mission endpoints require explicit authorization confirmation.
- Existing scope policy remains authoritative.
- Sensitive capabilities continue to require their existing approval controls.
