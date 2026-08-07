# HTTP API

Isopod exposes a localhost-only Axum API when `api_addr` is set (default `127.0.0.1:8787`). It is also started inline by `isopod daemon` and standalone by `isopod serve`.

```
isopod daemon --interval 60 --api 127.0.0.1:8787
isopod serve  --addr 127.0.0.1:8787
```

All responses are `application/json`. No auth by default — put a reverse proxy in front for external exposure.

## Endpoints

### `GET /health`

Liveness check.

**Response**

```json
{
  "status": "ok",
  "service": "isopod",
  "version": "0.1.0"
}
```

**Example**

```bash
curl http://127.0.0.1:8787/health | jq .
```

### `GET /compliance`

Aggregated control posture.

**Response**

```json
{
  "framework": "ISO27001",
  "total": 14,
  "passing": 3,
  "failing": 0,
  "warning": 0,
  "unknown": 11,
  "controls": [
    {
      "id": "ISO27001-A.8.15",
      "title": "Logging",
      "framework": "iso27001",
      "status": "PASS",
      "evidence_count": 5,
      "confidence": 0.85,
      "last_checked": "2026-08-07T11:00:07Z",
      "reason": null,
      "remediation": null
    }
  ]
}
```

**Posture score** — clients can compute `passing/total`. CLI shows a bar; API leaves calculation to the caller.

### `GET /evidence`

All evidence, newest first (limit 100 via API; `state.db` holds up to 100k, use `isopod export` for full).

**Response**

```json
{
  "count": 5,
  "evidence": [
    {
      "id": "f3dfccb5-…",
      "source": "system",
      "timestamp": "2026-08-07T11:00:07Z",
      "artifact_type": "certificate",
      "content_hash": "48573f…",
      "confidence": 0.85,
      "artifact_path": null,
      "control_id": "ISO27001-A.8.26",
      "provenance": null,
      "metadata": {"ca_bundle_present": true}
    }
  ]
}
```

Filter client-side:

```bash
curl http://127.0.0.1:8787/evidence | jq '.evidence[] | select(.control_id=="ISO27001-A.8.15")'
```

### `GET /drift`

Recent posture changes, newest first (limit 50).

**Response**

```json
{
  "drifts": [
    {
      "id": "d897fb…",
      "control_id": "ISO27001-A.8.15",
      "previous": "PASS",
      "current": "FAIL",
      "cause": "Confidence below threshold",
      "severity": "HIGH",
      "timestamp": "2026-08-07T11:02:00Z"
    }
  ]
}
```

Severity values: `HIGH`, `MEDIUM`, `LOW` (see `docs/controls.md`).

## CLI equivalents

| API | CLI |
|---|---|
| `GET /health` | `isopod status --json | jq .` |
| `GET /compliance` | `isopod status --json` |
| `GET /evidence` | `isopod evidence --limit 100 --json` |
| `GET /drift` | `isopod drift --json` |

`isopod export ./audit` is the offline audit bundle (`compliance.json`, `evidence.json`, `controls/*.yaml`).

## Error handling

- `200` on success with JSON body.
- `500` on store failure (rare; SQLite errors are logged via `tracing::warn` and return empty arrays instead of 500 in current implementation).

## Security

Bind to `127.0.0.1` by default. To expose externally, set `api_addr: "0.0.0.0:8787"` in `~/.isopod/config.yaml` and front with TLS + auth. No built-in auth; future roadmap includes mTLS and signed evidence.

## Programmatic use

Router is importable:

```rust
let store = Arc::new(Store::open_in_memory()?);
let app = isopod::api::router(store);
// use with axum::serve or tower::ServiceExt::oneshot in tests
```
