# Harness Safety API

Stateless four-axis harness classifier for IITM assignment.

- `POST /`: JSON envelope `{profile,batchId,policy,cases}`; returns `{profile,batchId,results}` with exactly one case-matched decision tuple per input case.
- `GET /health`: health check.
- Tested at container build via `tests.py`. No external model keys required.

The classifier is deterministic and heuristic. The hidden grader has not been run.
