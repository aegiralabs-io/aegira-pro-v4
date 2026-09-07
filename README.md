# Aegira Pro v4

Aegira is a Linux incident detection and automated recovery engine. v4 keeps the existing log-driven recovery model and adds Docker-aware event monitoring, exit-code rules, Docker health events, OOM events, HTTP health checks, container-local probes, arbitrary direct-command remediation, and richer recovery verification.

## What v4 handles

- Linux service incidents from watched log entries.
- Docker container `die` events without waiting for an error log.
- Docker exit-code matching, including user-defined codes.
- Docker `oom` events.
- Docker `health_status: unhealthy` events.
- Container-local probes such as `wget http://127.0.0.1:8080/health` through `docker exec`.
- Host-reachable HTTP API health checks.
- Service restart, container restart, direct executable commands, and `docker exec` remediation.
- `alert_only`, `dry_run`, and `approval_required` actions.
- Recovery verification through systemd, Docker state, HTTP status, or a command.
- Docker log-tail context attached to Docker incidents for diagnosis.
- Custom rules in `/etc/aegira/rules/custom/` with live reload.
- Custom rules can override a built-in rule with the same ID.
- Incident cooldowns and rotating incident logs.
- Existing Gmail/Composio alerting support.

## Important Docker behavior

Aegira listens to Docker events rather than relying only on application error logs. Docker emits `die`, `oom`, `health_status`, `start`, `stop`, and other container events. This means a container can be diagnosed even when the application produced no `[ERROR]` or `[CRITICAL]` line.

Aegira intentionally does **not** automatically restart every non-zero exit code. Some exit codes indicate configuration or command problems, and `143` is commonly associated with SIGTERM/manual stopping. Those built-ins are alert-only by default. A user can define an explicit rule for any exit code they want to recover from.

## Custom exit-code recovery

Example:

```json
{
  "id": "my_app_exit_42",
  "name": "My App Exit Code 42",
  "severity": "high",
  "trigger": {
    "type": "docker_exit",
    "container": "my-app",
    "exit_codes": [42]
  },
  "error_patterns": ["exited", "exit code 42"],
  "context_patterns": ["docker container"],
  "remediation": {
    "type": "command",
    "executable": "/usr/local/bin/recover-my-app",
    "args": ["my-app", "{EXIT_CODE}"]
  },
  "verification": {
    "type": "container_running",
    "container": "my-app"
  },
  "priority": 30
}
```

Supported placeholders in command arguments:

- `{CONTAINER}`
- `{EXIT_CODE}`
- `{INCIDENT}`
- `{SOURCE}`
- `{RULE_ID}`
- `{RULE_NAME}`

Commands are executed directly, not through a shell. This intentionally avoids turning every rule into an arbitrary shell-injection surface.

## Internal API recovery

If an API is inside a container and the container itself is still running, use a `container_probe` rule. The probe runs inside the target container. For example:

```json
{
  "id": "internal_api_probe",
  "name": "Internal API Probe",
  "severity": "critical",
  "trigger": {
    "type": "container_probe",
    "container": "my-app",
    "executable": "wget",
    "args": ["-q", "-O", "/dev/null", "http://127.0.0.1:8080/health"],
    "interval_secs": 5
  },
  "error_patterns": ["probe", "failed"],
  "context_patterns": ["my-app"],
  "remediation": {
    "type": "container_restart",
    "container": "my-app"
  },
  "verification": {
    "type": "container_running",
    "container": "my-app"
  },
  "priority": 35
}
```

If the API is reachable from the Aegira host, use `http_health` instead. The verification can then require an expected HTTP status.

## Commands

```text
aegira install
aegira status
aegira show-rules
aegira history
aegira docker-status <container>
aegira configure service <name>
aegira configure container <name>
aegira configure alerts <on|off> [recipient_email]
aegira license
aegira run
```

## Installation

Build on the target Linux host:

```bash
cargo build --release
sudo ./target/release/aegira install
```

Aegira installs itself as a systemd service and runs as root because service recovery and Docker daemon control require elevated privileges on normal Linux installations.

## Docker access and security

Aegira uses the Docker CLI and therefore the local Docker Engine socket/context available to the service. Access to the Docker daemon is highly privileged. Do not expose an unauthenticated Docker TCP socket. If Docker is remote, use a secured Docker context/SSH/TLS configuration.

Rules are powerful by design. Only trusted users should be allowed to modify `/etc/aegira/rules/custom/`.

## Pro licensing

The supplied v4 build keeps licensing disabled for development/testing. Production licensing should remain server-side: the binary should receive an entitlement state, while billing credentials, license-signing secrets, and the license database stay outside the client.

## Release checklist

Before selling/distributing v4:

1. Run `cargo fmt --check`.
2. Run `cargo check`.
3. Run `cargo test` if tests are present.
4. Build a release binary on every supported architecture.
5. Test a real Docker `die` event with a harmless container.
6. Test exit codes 126, 127, 137, 139, and 143.
7. Test Docker healthcheck transitions.
8. Test an internal container-local API probe.
9. Test a host-reachable HTTP health check.
10. Test custom rule override behavior.
11. Test dry-run and alert-only rules.
12. Test failed verification and manual-action alerts.
13. Test Aegira restart and Docker daemon restart behavior.
14. Package a signed release artifact.

Aegira is an automation/recovery tool, not a replacement for full observability. Its core job is to turn known failure signals into controlled, user-defined recovery actions while reducing repetitive manual intervention.
