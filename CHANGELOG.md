# Aegira v4.0.0

## Docker-aware recovery
- Docker event monitoring via `docker events`.
- Exit-code rules with user-defined exit-code matching.
- Docker OOM event handling.
- Docker health-status event handling.
- Container-local probe monitoring for APIs/processes inside a container.
- Host-reachable HTTP health monitoring.
- Docker log-tail context on container incidents.

## Recovery actions
- Service restart.
- Container restart.
- Direct arbitrary executable commands with placeholders.
- `docker exec` remediation.
- Alert-only, dry-run, and approval-required actions.

## Verification
- systemd active verification.
- Docker running verification.
- Docker healthy verification.
- Container-local probe verification.
- HTTP status verification.
- Command-success verification.

## Rule system
- Custom rules can override built-in rules with the same ID.
- Rules hot-reload while Aegira is running.
- Existing log-based rules remain compatible.
