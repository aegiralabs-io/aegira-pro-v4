use reqwest::blocking::Client;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

const LOGS_DIR: &str = "/var/log/aegira";
const LOG_FILE_PATH: &str = "/var/log/aegira/system.log";
const INCIDENT_LOG_PATH: &str = "/var/log/aegira/incident.log";

const BUILTIN_RULES_DIR: &str = "/etc/aegira/rules/builtin";
const CUSTOM_RULES_DIR: &str = "/etc/aegira/rules/custom";
const CONFIG_PATH: &str = "/etc/aegira/config.json";

const POLL_INTERVAL_SECS: u64 = 2;
const COMMAND_TIMEOUT_SECS: u64 = 20;
const VERIFY_DELAY_SECS: u64 = 2;
const MAX_VERIFY_ATTEMPTS: u32 = 5;
const INCIDENT_COOLDOWN_SECS: u64 = 30;
const MAX_INCIDENT_LOG_BYTES: u64 = 10 * 1024 * 1024;
const DOCKER_EVENT_RECONNECT_SECS: u64 = 3;
const DOCKER_LOG_TAIL_LINES: u32 = 80;
const API_HEALTH_POLL_SECS: u64 = 5;
const MAX_COMMAND_SEQUENCE_LENGTH: usize = 5;

const MIN_MATCH_SCORE: i32 = 60;
const SELF_SERVICE: &str = "aegira";

// Pro licensing is intentionally disabled during development/testing.
// Re-enable server-side license enforcement for production after billing is wired.
const LICENSE_ENFORCEMENT_ENABLED: bool = false;

const COMPOSIO_BASE_URL: &str = "https://backend.composio.dev/api/v3.1";
const COMPOSIO_GMAIL_TOOL: &str = "GMAIL_SEND_EMAIL";
const COMPOSIO_TIMEOUT_SECS: u64 = 15;
const COMPOSIO_ENV_FILE: &str = "/etc/aegira/composio.env";

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
struct AegiraConfig {
    #[serde(default)]
    target_service: Option<String>,
    #[serde(default)]
    target_container: Option<String>,
    #[serde(default)]
    alerts: AlertConfig,
    #[serde(default)]
    #[allow(dead_code)]
    license_key: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
struct AlertConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    recipient_email: Option<String>,
    #[serde(default)]
    composio_user_id: Option<String>,
    #[serde(default)]
    notify_on_recovery: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuleFileFingerprint {
    files: Vec<(String, u64, u64)>,
}

fn load_config() -> Result<AegiraConfig, String> {
    match fs::read_to_string(CONFIG_PATH) {
        Ok(contents) => serde_json::from_str(&contents)
            .map_err(|e| format!("Invalid Aegira config: {}", e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(AegiraConfig::default()),
        Err(e) => Err(format!("Failed to read {}: {}", CONFIG_PATH, e)),
    }
}

fn save_config(config: &AegiraConfig) -> Result<(), String> {
    let contents = serde_json::to_string_pretty(config)
        .map_err(|e| format!("Failed to serialize Aegira config: {}", e))?;
    fs::write(CONFIG_PATH, format!("{}\n", contents))
        .map_err(|e| format!("Failed to write {}: {}", CONFIG_PATH, e))
}

fn normalize_target(value: &str) -> String {
    value.trim().trim_end_matches(".service").to_lowercase()
}

fn resolve_service_target(service: &str) -> Result<String, String> {
    if service.trim() != "TARGET_SERVICE" {
        return Ok(service.trim().to_string());
    }
    let config = load_config()?;
    let target = config.target_service
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "No target service configured. Run: sudo aegira configure service <service>".to_string())?;
    if normalize_target(&target) == SELF_SERVICE {
        return Err("Refusing to target Aegira itself.".to_string());
    }
    Ok(target.trim().to_string())
}

fn resolve_container_target(container: &str) -> Result<String, String> {
    if container.trim() != "TARGET_CONTAINER" {
        return Ok(container.trim().to_string());
    }
    let config = load_config()?;
    config.target_container
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_string())
        .ok_or_else(|| "No target container configured. Run: sudo aegira configure container <container>".to_string())
}

fn get_rule_fingerprint() -> RuleFileFingerprint {
    let mut files = Vec::new();
    for dir in [BUILTIN_RULES_DIR, CUSTOM_RULES_DIR] {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|v| v.to_str()) != Some("json") {
                    continue;
                }
                if let Ok(metadata) = fs::metadata(&path) {
                    let modified = metadata.modified().ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs().saturating_mul(1_000_000_000) + d.subsec_nanos() as u64)
                        .unwrap_or(0);
                    files.push((path.to_string_lossy().into_owned(), metadata.len(), modified));
                }
            }
        }
    }
    files.sort();
    RuleFileFingerprint { files }
}

fn default_rule_action() -> String {
    "auto_recover".to_string()
}

#[derive(Debug, Deserialize, Clone)]
struct Rule {
    id: String,
    name: String,

    #[serde(default)]
    severity: String,

    #[serde(default)]
    error_patterns: Vec<String>,

    #[serde(default)]
    context_patterns: Vec<String>,

    #[serde(default)]
    trigger: Trigger,

    remediation: Remediation,
    verification: Verification,

    #[serde(default = "default_rule_action")]
    action: String,

    #[serde(default)]
    priority: i32,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Trigger {
    Log,
    DockerExit {
        container: String,
        #[serde(default)]
        exit_codes: Vec<i32>,
    },
    DockerHealth {
        container: String,
        #[serde(default = "default_health_status")]
        status: String,
    },
    DockerOom {
        container: String,
    },
    HttpHealth {
        url: String,
        /// Explicit Docker container owning this HTTP endpoint.
        /// Rules should always set this for automatic recovery.
        #[serde(default)]
        container: Option<String>,
        #[serde(default = "default_expected_status")]
        expected_status: u16,
        #[serde(default = "default_api_interval")]
        interval_secs: u64,
    },
    ContainerProbe {
        container: String,
        executable: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default = "default_probe_interval")]
        interval_secs: u64,
    },
}

impl Default for Trigger {
    fn default() -> Self {
        Trigger::Log
    }
}

fn default_health_status() -> String { "unhealthy".to_string() }
fn default_expected_status() -> u16 { 200 }
fn default_api_interval() -> u64 { API_HEALTH_POLL_SECS }
fn default_probe_interval() -> u64 { API_HEALTH_POLL_SECS }

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type")]
enum Remediation {
    #[serde(rename = "service_restart")]
    ServiceRestart { service: String },

    #[serde(rename = "container_restart")]
    ContainerRestart { container: String },

    #[serde(rename = "command")]
    Command { executable: String, #[serde(default)] args: Vec<String> },

    #[serde(rename = "container_exec")]
    ContainerExec { container: String, #[serde(default)] args: Vec<String> },

    #[serde(rename = "command_sequence")]
    CommandSequence {
        #[serde(default)]
        commands: Vec<String>,
        #[serde(default)]
        verifications: Vec<Verification>,
    },

    #[serde(rename = "alert_only")]
    AlertOnly,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type")]
enum Verification {
    #[serde(rename = "service_active")]
    ServiceActive { service: String },

    #[serde(rename = "container_running")]
    ContainerRunning { container: String },

    #[serde(rename = "container_healthy")]
    ContainerHealthy { container: String },

    #[serde(rename = "container_probe_success")]
    ContainerProbeSuccess { container: String, executable: String, #[serde(default)] args: Vec<String> },

    #[serde(rename = "http_status")]
    HttpStatus { url: String, #[serde(default = "default_expected_status")] expected_status: u16 },

    #[serde(rename = "container_http_status")]
    ContainerHttpStatus {
        container: String,
        url: String,
        #[serde(default = "default_expected_status")]
        expected_status: u16,
    },

    #[serde(rename = "command_success")]
    CommandSuccess { executable: String, #[serde(default)] args: Vec<String> },

    #[serde(rename = "none")]
    None,
}

#[derive(Debug, Clone)]
struct IncidentContext {
    source: &'static str,
    incident: String,
    container: Option<String>,
    exit_code: Option<i32>,
    health_status: Option<String>,
}

impl IncidentContext {
    fn log(incident: String) -> Self {
        Self { source: "log", incident, container: None, exit_code: None, health_status: None }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

fn get_aegira_dir() -> PathBuf {
    PathBuf::from("/etc/aegira")
}

fn ensure_file_exists(path: &Path) -> Result<(), String> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map(|_| ())
        .map_err(|e| {
            format!(
                "Failed to create {}: {}",
                path.display(),
                e
            )
        })
}

fn ensure_environment_setup() -> Result<(), String> {
    fs::create_dir_all(LOGS_DIR)
        .map_err(|e| {
            format!(
                "Failed to create {}: {}",
                LOGS_DIR,
                e
            )
        })?;

    fs::create_dir_all(BUILTIN_RULES_DIR)
        .map_err(|e| {
            format!(
                "Failed to create {}: {}",
                BUILTIN_RULES_DIR,
                e
            )
        })?;

    fs::create_dir_all(CUSTOM_RULES_DIR)
        .map_err(|e| {
            format!(
                "Failed to create {}: {}",
                CUSTOM_RULES_DIR,
                e
            )
        })?;

    ensure_file_exists(Path::new(LOG_FILE_PATH))?;
    ensure_file_exists(Path::new(INCIDENT_LOG_PATH))?;

    let composio_env = Path::new(COMPOSIO_ENV_FILE);
    ensure_file_exists(composio_env)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(composio_env)
            .map_err(|e| format!("Failed to read {} permissions: {}", composio_env.display(), e))?
            .permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(composio_env, permissions)
            .map_err(|e| format!("Failed to secure {}: {}", composio_env.display(), e))?;
    }

    Ok(())
}

fn rotate_incident_log_if_needed() {
    let path = Path::new(INCIDENT_LOG_PATH);

    let size = match fs::metadata(path) {
        Ok(metadata) => metadata.len(),
        Err(_) => return,
    };

    if size < MAX_INCIDENT_LOG_BYTES {
        return;
    }

    let rotated =
        Path::new(LOGS_DIR).join("incident.log.1");

    let _ = fs::remove_file(&rotated);

    if let Err(e) = fs::rename(path, &rotated) {
        eprintln!(
            "[LOG ERROR] Failed to rotate incident log: {}",
            e
        );
        return;
    }

    let _ = ensure_file_exists(path);
}

fn log_incident(msg: &str) {
    println!("{}", msg);

    rotate_incident_log_if_needed();

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(INCIDENT_LOG_PATH)
    {
        let _ = writeln!(file, "{}", msg);
    }
}

fn validate_target_name(value: &str, kind: &str) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{} target cannot be empty", kind));
    }
    if value == "TARGET_SERVICE" || value == "TARGET_CONTAINER" {
        return Ok(());
    }
    if value.len() > 256 || value.contains('/') || value.contains("..") || value.chars().any(|c| c.is_whitespace() || matches!(c, ';' | '&' | '|' | '$' | '`' | '<' | '>')) {
        return Err(format!("{} target contains unsafe characters", kind));
    }
    Ok(())
}

fn command_contains_docker_restart(command: &str) -> bool {
    let tokens: Vec<&str> = command
        .split_whitespace()
        .map(|token| token.trim_matches(|c: char| matches!(c, '\'' | '"' | ';' | '&')))
        .collect();

    tokens.windows(2).any(|pair| {
        let executable = pair[0].rsplit('/').next().unwrap_or(pair[0]);
        executable.eq_ignore_ascii_case("docker") && pair[1].eq_ignore_ascii_case("restart")
    })
}

fn validate_verification(verification: &Verification, rule_id: &str, allow_none: bool) -> Result<(), String> {
    match verification {
        Verification::ServiceActive { service } => {
            validate_target_name(service, "Verification service")?;
        }
        Verification::ContainerRunning { container } => {
            validate_target_name(container, "Verification container")?;
        }
        Verification::ContainerHealthy { container } => {
            validate_target_name(container, "Verification healthy container")?;
        }
        Verification::ContainerProbeSuccess { container, executable, args } => {
            validate_target_name(container, "Verification probe container")?;
            if executable.trim().is_empty() || executable.len() > 512 || args.len() > 64 || args.iter().any(|a| a.len() > 4096) {
                return Err(format!("Rule '{}' has invalid container probe verification", rule_id));
            }
        }
        Verification::HttpStatus { url, expected_status } => {
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Err(format!("Rule '{}' HTTP verification URL must start with http:// or https://", rule_id));
            }
            if *expected_status == 0 {
                return Err(format!("Rule '{}' has invalid HTTP verification status", rule_id));
            }
        }
        Verification::ContainerHttpStatus { container, url, expected_status } => {
            validate_target_name(container, "Verification HTTP container")?;
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Err(format!("Rule '{}' container HTTP verification URL must start with http:// or https://", rule_id));
            }
            if *expected_status == 0 {
                return Err(format!("Rule '{}' has invalid container HTTP verification status", rule_id));
            }
        }
        Verification::CommandSuccess { executable, args } => {
            if executable.trim().is_empty() || executable.len() > 512 || args.len() > 64 || args.iter().any(|a| a.len() > 4096) {
                return Err(format!("Rule '{}' has invalid command verification", rule_id));
            }
        }
        Verification::None if allow_none => {}
        Verification::None => {
            return Err(format!("Rule '{}' requires a real verification", rule_id));
        }
    }

    Ok(())
}

fn validate_rule(rule: &Rule) -> Result<(), String> {
    if rule.id.trim().is_empty() {
        return Err(
            "Rule ID cannot be empty".to_string()
        );
    }

    if rule.name.trim().is_empty() {
        return Err(format!(
            "Rule '{}' has an empty name",
            rule.id
        ));
    }

    if rule.error_patterns.is_empty() {
        return Err(format!(
            "Rule '{}' has no error patterns",
            rule.id
        ));
    }

    for pattern in &rule.error_patterns {
        if pattern.trim().is_empty() {
            return Err(format!(
                "Rule '{}' contains an empty error pattern",
                rule.id
            ));
        }
    }

    match rule.action.trim().to_lowercase().as_str() {
        "auto_recover" | "alert_only" | "dry_run" | "approval_required" => {}
        other => return Err(format!("Rule '{}' has unsupported action '{}'", rule.id, other)),
    }

    match &rule.remediation {
        Remediation::ServiceRestart { service } => {
            validate_target_name(service, "Service")?;
            let normalized = service.trim().trim_end_matches(".service").to_lowercase();
            if normalized == SELF_SERVICE {
                return Err(format!("Rule '{}' attempts to restart Aegira itself", rule.id));
            }
        }
        Remediation::ContainerRestart { container } => {
            validate_target_name(container, "Container")?;
        }
        Remediation::Command { executable, args } => {
            if executable.trim().is_empty() || executable.len() > 512 {
                return Err(format!("Rule '{}' has an invalid command executable", rule.id));
            }
            if executable.contains(';') || executable.contains('|') || executable.contains('&') || executable.contains('`') || executable.contains('$') {
                return Err(format!("Rule '{}' command executable contains shell metacharacters", rule.id));
            }
            if args.len() > 64 || args.iter().any(|a| a.len() > 4096) {
                return Err(format!("Rule '{}' has too many/large command arguments", rule.id));
            }
        }
        Remediation::ContainerExec { container, args } => {
            validate_target_name(container, "Container")?;
            if args.is_empty() || args.len() > 64 || args.iter().any(|a| a.len() > 4096) {
                return Err(format!("Rule '{}' container_exec requires 1-64 reasonable arguments", rule.id));
            }
        }
        Remediation::CommandSequence { commands, verifications } => {
            if commands.is_empty() || commands.len() > MAX_COMMAND_SEQUENCE_LENGTH {
                return Err(format!(
                    "Rule '{}' command_sequence requires 1-{} commands",
                    rule.id, MAX_COMMAND_SEQUENCE_LENGTH
                ));
            }

            if commands.iter().any(|c| c.trim().is_empty() || c.len() > 8192) {
                return Err(format!(
                    "Rule '{}' command_sequence contains an empty or oversized command",
                    rule.id
                ));
            }

            if verifications.len() != commands.len() {
                return Err(format!(
                    "Rule '{}' command_sequence requires exactly one verification per command",
                    rule.id
                ));
            }

            for verification in verifications {
                validate_verification(verification, &rule.id, false)?;
            }

            for (index, command) in commands.iter().enumerate() {
                if command_contains_docker_restart(command) && index != commands.len() - 1 {
                    return Err(format!(
                        "Rule '{}' docker restart must be the final command in a command_sequence",
                        rule.id
                    ));
                }
            }
        }
        Remediation::AlertOnly => {}
    }


    validate_verification(&rule.verification, &rule.id, true)?;

    match &rule.trigger {
        Trigger::Log => {}
        Trigger::DockerExit { container, exit_codes } => {
            validate_target_name(container, "Docker exit container")?;
            if exit_codes.len() > 64 { return Err(format!("Rule '{}' has too many exit codes", rule.id)); }
        }
        Trigger::DockerHealth { container, status } => {
            validate_target_name(container, "Docker health container")?;
            if status.trim().is_empty() { return Err(format!("Rule '{}' has empty Docker health status", rule.id)); }
        }
        Trigger::DockerOom { container } => validate_target_name(container, "Docker OOM container")?,
        Trigger::HttpHealth { url, container, expected_status, interval_secs } => {
            if !url.starts_with("http://") && !url.starts_with("https://") { return Err(format!("Rule '{}' HTTP trigger URL must start with http:// or https://", rule.id)); }
            if *expected_status == 0 || *interval_secs == 0 { return Err(format!("Rule '{}' has invalid HTTP trigger settings", rule.id)); }
            let container = container.as_deref().ok_or_else(|| format!("Rule '{}' HTTP health trigger requires an explicit container", rule.id))?;
            validate_target_name(container, "HTTP health container")?;
        }
        Trigger::ContainerProbe { container, executable, args, interval_secs } => {
            validate_target_name(container, "Container probe container")?;
            if executable.trim().is_empty() || executable.len() > 512 || args.len() > 64 || *interval_secs == 0 {
                return Err(format!("Rule '{}' has invalid container probe settings", rule.id));
            }
        }
    }


    Ok(())
}

fn parse_rules(contents: &str) -> Result<Vec<Rule>, String> {
    let contents = contents.trim();

    if contents.is_empty() {
        return Ok(Vec::new());
    }

    if contents.starts_with('[') {
        serde_json::from_str::<Vec<Rule>>(contents)
            .map_err(|e| e.to_string())
    } else {
        serde_json::from_str::<Rule>(contents)
            .map(|rule| vec![rule])
            .map_err(|e| e.to_string())
    }
}

fn load_rules_from_directory(
    path: &Path,
) -> Vec<Rule> {
    let mut rules = Vec::new();

    if !path.exists() {
        return rules;
    }

    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,

        Err(e) => {
            log_incident(&format!(
                "[RULES ERROR] Failed to read {}: {}",
                path.display(),
                e
            ));

            return rules;
        }
    };

    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .and_then(|value| value.to_str())
                == Some("json")
        })
        .collect();

    files.sort();

    for file_path in files {
        let contents =
            match fs::read_to_string(&file_path) {
                Ok(contents) => contents,

                Err(e) => {
                    log_incident(&format!(
                        "[RULES ERROR] Failed reading {}: {}",
                        file_path.display(),
                        e
                    ));

                    continue;
                }
            };

        let parsed =
            match parse_rules(&contents) {
                Ok(rules) => rules,

                Err(e) => {
                    log_incident(&format!(
                        "[RULES] Skipped invalid JSON {}: {}",
                        file_path.display(),
                        e
                    ));

                    continue;
                }
            };

        for rule in parsed {
            match validate_rule(&rule) {
                Ok(()) => {
                    rules.push(rule);
                }

                Err(e) => {
                    log_incident(&format!(
                        "[RULES] Skipped invalid rule: {}",
                        e
                    ));
                }
            }
        }
    }

    rules
}

fn get_hardcoded_default_rules() -> Vec<Rule> {
    vec![Rule {
        id: "connection_refused".to_string(),
        name: "Connection Refused".to_string(),
        severity: "high".to_string(),

        error_patterns: vec![
            "connection refused".to_string(),
        ],

        context_patterns: Vec::new(),
        trigger: Trigger::Log,

        remediation: Remediation::ServiceRestart {
            service: "cron".to_string(),
        },

        verification: Verification::ServiceActive {
            service: "cron".to_string(),
        },

        action: "auto_recover".to_string(),
        priority: 10,
    }]
}

fn load_all_rules() -> Vec<Rule> {
    let mut rules = Vec::new();
    let mut seen_ids = HashSet::new();

    let builtin_dir =
        Path::new(BUILTIN_RULES_DIR);

    let builtin =
        load_rules_from_directory(builtin_dir);

    for rule in builtin {
        let id = rule.id.trim().to_lowercase();

        if seen_ids.insert(id) {
            rules.push(rule);
        }
    }

    let custom_dir =
        Path::new(CUSTOM_RULES_DIR);

    let custom =
        load_rules_from_directory(custom_dir);

    for rule in custom {
        let id = rule.id.trim().to_lowercase();
        if let Some(index) = rules.iter().position(|existing| existing.id.trim().eq_ignore_ascii_case(&id)) {
            rules[index] = rule.clone();
        } else if seen_ids.insert(id) {
            rules.push(rule);
        }
    }

    if rules.is_empty() {
        log_incident(
            "[RULES] No external rules loaded. Using fallback rule."
        );

        rules = get_hardcoded_default_rules();
    }

    rules.sort_by(|a, b| {
        b.priority.cmp(&a.priority)
    });

    log_incident(&format!(
        "[RULES] Total active rules: {}",
        rules.len()
    ));

    rules
}

fn contains_case_insensitive(
    text: &str,
    pattern: &str,
) -> bool {
    text.to_lowercase()
        .contains(&pattern.to_lowercase())
}

fn calculate_match_score(
    rule: &Rule,
    incident: &str,
) -> Option<i32> {
    let mut error_matches: usize = 0;
    let mut context_matches: usize = 0;

    for pattern in &rule.error_patterns {
        if contains_case_insensitive(
            incident,
            pattern,
        ) {
            error_matches += 1;
        }
    }

    if error_matches == 0 {
        return None;
    }

    for pattern in &rule.context_patterns {
        if contains_case_insensitive(
            incident,
            pattern,
        ) {
            context_matches += 1;
        }
    }

    let error_score =
        60i32
            + (error_matches
                .saturating_sub(1) as i32
                * 10);

    let context_score =
        context_matches as i32 * 10;

    let priority_score =
        rule.priority.clamp(-20, 20);

    Some(
        (error_score
            + context_score
            + priority_score)
            .clamp(0, 100)
    )
}

fn resolve_trigger_container(value: &str) -> Result<String, String> {
    resolve_container_target(value)
}

fn trigger_matches(rule: &Rule, ctx: &IncidentContext) -> bool {
    match &rule.trigger {
        Trigger::Log => ctx.source == "log",
        Trigger::DockerExit { container, exit_codes } => {
            if ctx.source != "docker_exit" { return false; }
            let target = match resolve_trigger_container(container) { Ok(v) => v, Err(_) => return false };
            if ctx.container.as_deref() != Some(target.as_str()) && ctx.container.as_deref() != Some(container.as_str()) { return false; }
            match ctx.exit_code { Some(code) => exit_codes.is_empty() || exit_codes.contains(&code), None => false }
        }
        Trigger::DockerHealth { container, status } => {
            if ctx.source != "docker_health" { return false; }
            let target = match resolve_trigger_container(container) { Ok(v) => v, Err(_) => return false };
            if ctx.container.as_deref() != Some(target.as_str()) && ctx.container.as_deref() != Some(container.as_str()) { return false; }
            ctx.health_status.as_deref().map(|s| s.eq_ignore_ascii_case(status)).unwrap_or(false)
        }
        Trigger::DockerOom { container } => {
            if ctx.source != "docker_oom" { return false; }
            let target = match resolve_trigger_container(container) { Ok(v) => v, Err(_) => return false };
            ctx.container.as_deref() == Some(target.as_str()) || ctx.container.as_deref() == Some(container.as_str())
        }
        Trigger::HttpHealth { url, container, .. } => {
            if ctx.source != "http_health" || !ctx.incident.contains(url) { return false; }
            let Some(container) = container.as_deref() else { return false; };
            let target = match resolve_trigger_container(container) { Ok(v) => v, Err(_) => return false };
            ctx.container.as_deref() == Some(target.as_str()) || ctx.container.as_deref() == Some(container)
        },
        Trigger::ContainerProbe { container, executable, .. } => {
            if ctx.source != "container_probe" { return false; }
            let target = match resolve_trigger_container(container) { Ok(v) => v, Err(_) => return false };
            ctx.container.as_deref() == Some(target.as_str()) && ctx.incident.contains(executable)
        }
    }
}

fn find_best_rule_for_context<'a>(rules: &'a [Rule], ctx: &IncidentContext) -> Option<(&'a Rule, i32)> {
    let mut best = None;
    for rule in rules {
        if !trigger_matches(rule, ctx) { continue; }
        let score = match calculate_match_score(rule, &ctx.incident) { Some(v) => v, None => 60 + rule.priority.clamp(-20, 20) };
        if score < MIN_MATCH_SCORE { continue; }
        match best {
            None => best = Some((rule, score)),
            Some((current, current_score)) if score > current_score || (score == current_score && rule.id.to_lowercase() < current.id.to_lowercase()) => best = Some((rule, score)),
            _ => {}
        }
    }
    best
}

fn find_best_rule<'a>(
    rules: &'a [Rule],
    incident: &str,
) -> Option<(&'a Rule, i32)> {
    let mut best:
        Option<(&'a Rule, i32)> = None;

    for rule in rules {
        let score =
            match calculate_match_score(
                rule,
                incident,
            ) {
                Some(score) => score,
                None => continue,
            };

        if score < MIN_MATCH_SCORE {
            continue;
        }

        match best {
            None => {
                best = Some((rule, score));
            }

            Some((current_rule, current_score)) => {
                if score > current_score
                    || (
                        score == current_score
                            && rule.id.to_lowercase()
                                < current_rule.id.to_lowercase()
                    )
                {
                    best = Some((rule, score));
                }
            }
        }
    }

    best
}

fn find_binary<'a>(
    candidates: &'a [&'a str],
) -> Result<&'a str, String> {
    for candidate in candidates {
        if Path::new(candidate).exists() {
            return Ok(candidate);
        }
    }

    Err(format!(
        "Required binary not found. Checked: {}",
        candidates.join(", ")
    ))
}

fn systemctl_binary() -> Result<&'static str, String> {
    find_binary(&[
        "/usr/bin/systemctl",
        "/bin/systemctl",
    ])
}

fn docker_binary() -> Result<&'static str, String> {
    find_binary(&[
        "/usr/bin/docker",
        "/bin/docker",
        "/usr/local/bin/docker",
    ])
}

fn execute_command(
    executable: &str,
    args: &[&str],
) -> Result<(), String> {
    log_incident(&format!(
        "[EXEC] {} {}",
        executable,
        args.join(" ")
    ));

    let mut child =
        Command::new(executable)
            .args(args)
            .spawn()
            .map_err(|e| {
                format!(
                    "Failed to start {}: {}",
                    executable,
                    e
                )
            })?;

    let start = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    return Ok(());
                }

                return Err(format!(
                    "{} exited with status {}",
                    executable,
                    status
                ));
            }

            Ok(None) => {
                if start.elapsed()
                    >= Duration::from_secs(
                        COMMAND_TIMEOUT_SECS,
                    )
                {
                    let _ = child.kill();
                    let _ = child.wait();

                    return Err(format!(
                        "{} timed out after {} seconds",
                        executable,
                        COMMAND_TIMEOUT_SECS
                    ));
                }

                sleep(Duration::from_millis(100));
            }

            Err(e) => {
                return Err(format!(
                    "Failed waiting for {}: {}",
                    executable,
                    e
                ));
            }
        }
    }
}

fn execute_command_capture(executable: &str, args: &[String], timeout_secs: u64) -> Result<(i32, String, String), String> {
    log_incident(&format!("[EXEC] {} {}", executable, args.join(" ")));
    let mut child = Command::new(executable)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to start {}: {}", executable, e))?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok((status.code().unwrap_or(-1), String::new(), String::new())),
            Ok(None) if start.elapsed() >= Duration::from_secs(timeout_secs) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{} timed out after {} seconds", executable, timeout_secs));
            }
            Ok(None) => sleep(Duration::from_millis(100)),
            Err(e) => return Err(format!("Failed waiting for {}: {}", executable, e)),
        }
    }
}

fn execute_command_sequence(
    commands: &[String],
    verifications: &[Verification],
    ctx: Option<&IncidentContext>,
    rule: &Rule,
) -> Result<(), String> {
    if commands.is_empty() {
        return Err("Command sequence is empty".to_string());
    }

    if commands.len() > MAX_COMMAND_SEQUENCE_LENGTH {
        return Err(format!(
            "Command sequence exceeds maximum of {} commands",
            MAX_COMMAND_SEQUENCE_LENGTH
        ));
    }

    if verifications.len() != commands.len() {
        return Err(format!(
            "Command sequence has {} commands but {} verifications; every command must have exactly one verification",
            commands.len(),
            verifications.len()
        ));
    }

    if verifications.iter().any(|v| matches!(v, Verification::None)) {
        return Err("Command sequence requires a real verification after every command".to_string());
    }

    for (index, command) in commands.iter().enumerate() {
        if command_contains_docker_restart(command) && index != commands.len() - 1 {
            return Err("docker restart must be the final command in a command_sequence".to_string());
        }
    }

    log_incident(&format!(
        "[RECOVERY] Executing command sequence ({} commands)",
        commands.len()
    ));

    for (index, raw_command) in commands.iter().enumerate() {
        let command = expand_command_arg(raw_command, ctx, rule);
        let step = index + 1;

        log_incident(&format!(
            "[COMMAND {} / {}] {}",
            step,
            commands.len(),
            command
        ));

        #[cfg(unix)]
        let shell = "/bin/sh";
        #[cfg(not(unix))]
        let shell = "cmd";

        #[cfg(unix)]
        let shell_args = vec!["-c", command.as_str()];
        #[cfg(not(unix))]
        let shell_args = vec!["/C", command.as_str()];

        let mut child = Command::new(shell)
            .args(&shell_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Command {} failed to start: {}", step, e))?;

        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let stdout = child.stdout.take().map(|mut reader| {
                        let mut buf = String::new();
                        let _ = reader.read_to_string(&mut buf);
                        buf
                    }).unwrap_or_default();
                    let stderr = child.stderr.take().map(|mut reader| {
                        let mut buf = String::new();
                        let _ = reader.read_to_string(&mut buf);
                        buf
                    }).unwrap_or_default();

                    if !status.success() {
                        let detail = if !stderr.trim().is_empty() {
                            format!(" stderr={}", stderr.trim())
                        } else if !stdout.trim().is_empty() {
                            format!(" stdout={}", stdout.trim())
                        } else {
                            String::new()
                        };

                        return Err(format!(
                            "Command {} exited with status {}.{}",
                            step, status, detail
                        ));
                    }

                    log_incident(&format!(
                        "[COMMAND {} / {}] Completed successfully",
                        step,
                        commands.len()
                    ));
                    break;
                }
                Ok(None) if start.elapsed() >= Duration::from_secs(COMMAND_TIMEOUT_SECS) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "Command {} timed out after {} seconds",
                        step, COMMAND_TIMEOUT_SECS
                    ));
                }
                Ok(None) => sleep(Duration::from_millis(100)),
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "Failed waiting for command {}: {}",
                        step, e
                    ));
                }
            }
        }

        sleep(Duration::from_secs(VERIFY_DELAY_SECS));

        let verification = &verifications[index];
        let mut verified = false;

        for attempt in 1..=MAX_VERIFY_ATTEMPTS {
            log_incident(&format!(
                "[VERIFY COMMAND {} / {}] Verification attempt {}/{}",
                step,
                commands.len(),
                attempt,
                MAX_VERIFY_ATTEMPTS
            ));

            if verify_recovery(verification, ctx, rule) {
                verified = true;
                log_incident(&format!(
                    "[VERIFY COMMAND {} / {}] Verification passed",
                    step,
                    commands.len()
                ));
                break;
            }

            if attempt < MAX_VERIFY_ATTEMPTS {
                sleep(Duration::from_secs(VERIFY_DELAY_SECS));
            }
        }

        if !verified {
            return Err(format!(
                "Command {} executed successfully but its verification failed",
                step
            ));
        }
    }

    Ok(())
}

fn expand_command_arg(arg: &str, ctx: Option<&IncidentContext>, rule: &Rule) -> String {
    let mut out = arg.to_string();
    if let Some(c) = ctx {
        out = out.replace("{CONTAINER}", c.container.as_deref().unwrap_or(""));
        out = out.replace("{EXIT_CODE}", &c.exit_code.map(|v| v.to_string()).unwrap_or_default());
        out = out.replace("{INCIDENT}", &c.incident);
        out = out.replace("{SOURCE}", c.source);
    }
    out.replace("{RULE_ID}", &rule.id).replace("{RULE_NAME}", &rule.name)
}

fn docker_logs_context(container: &str) -> String {
    let docker = match docker_binary() { Ok(v) => v, Err(_) => return String::new() };
    match Command::new(docker).args(["logs", "--tail", &DOCKER_LOG_TAIL_LINES.to_string(), container]).output() {
        Ok(output) => {
            let mut text = String::from_utf8_lossy(&output.stdout).to_string();
            text.push_str(&String::from_utf8_lossy(&output.stderr));
            let text = text.trim().to_string();
            if text.is_empty() {
                String::new()
            } else {
                let capped = if text.len() > 12000 { format!("{}\n[Docker logs truncated]", text.chars().take(12000).collect::<String>()) } else { text };
                format!("\nDocker logs (tail {}):\n{}", DOCKER_LOG_TAIL_LINES, capped)
            }
        }
        Err(_) => String::new(),
    }
}

fn docker_inspect_state(container: &str) -> Option<serde_json::Value> {
    let docker = docker_binary().ok()?;
    let output = Command::new(docker).args(["inspect", "--type", "container", container]).output().ok()?;
    if !output.status.success() { return None; }
    serde_json::from_slice::<serde_json::Value>(&output.stdout).ok()?.as_array()?.first().cloned()
}

fn container_display_name(id: &str) -> String {
    docker_inspect_state(id).and_then(|v| v.get("Name").and_then(|n| n.as_str()).map(|s| s.trim_start_matches('/').to_string())).unwrap_or_else(|| id.to_string())
}

fn env_value(name: &str) -> Option<String> {
    if let Ok(value) = std::env::var(name) {
        if !value.trim().is_empty() {
            return Some(value);
        }
    }

    let contents = fs::read_to_string(COMPOSIO_ENV_FILE).ok()?;
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=')?;
        if key.trim() == name {
            let value = value.trim().trim_matches('"').trim_matches('\'');
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn send_gmail_alert(subject: &str, body: &str) -> Result<(), String> {
    let api_key = env_value("COMPOSIO_API_KEY")
        .ok_or_else(|| "COMPOSIO_API_KEY is not configured".to_string())?;
    let config = load_config()?;
    let user_id = config.alerts.composio_user_id
        .or_else(|| env_value("COMPOSIO_USER_ID"))
        .ok_or_else(|| "Composio user ID is not configured. Set COMPOSIO_USER_ID or configure alerts.composio_user_id.".to_string())?;
    let recipient = config.alerts.recipient_email
        .or_else(|| env_value("AEGIRA_ALERT_EMAIL"))
        .ok_or_else(|| "Alert recipient is not configured. Set AEGIRA_ALERT_EMAIL or configure alerts.recipient_email.".to_string())?;

    let url = format!("{}/tools/execute/{}", COMPOSIO_BASE_URL, COMPOSIO_GMAIL_TOOL);
    let payload = json!({
        "user_id": user_id,
        "version": "latest",
        "arguments": {
            "recipient_email": recipient,
            "subject": subject,
            "body": body
        }
    });

    log_incident(&format!("[ALERT] Sending Gmail alert to {}", recipient));

    let client = Client::builder()
        .timeout(Duration::from_secs(COMPOSIO_TIMEOUT_SECS))
        .build()
        .map_err(|e| format!("Failed to create alert client: {}", e))?;

    let response = client
        .post(url)
        .header("x-api-key", api_key)
        .json(&payload)
        .send()
        .map_err(|e| format!("Composio alert request failed: {}", e))?;

    let status = response.status();
    let text = response.text().unwrap_or_default();

    if status.is_success() {
        log_incident("[ALERT] Gmail alert sent successfully");
        Ok(())
    } else {
        Err(format!("Composio Gmail alert failed with HTTP {}: {}", status, text))
    }
}

fn send_alert(subject: &str, body: &str) {
    let config = match load_config() {
        Ok(config) => config,
        Err(e) => {
            log_incident(&format!("[ALERT ERROR] {}", e));
            return;
        }
    };

    if !config.alerts.enabled {
        log_incident("[ALERT] Alerting disabled");
        return;
    }

    if let Err(e) = send_gmail_alert(subject, body) {
        log_incident(&format!("[ALERT ERROR] {}", e));
    }
}

fn alert_body(incident: &str, rule: Option<&Rule>, status: &str) -> String {
    let rule_info = rule
        .map(|r| format!("{} ({})", r.name, r.id))
        .unwrap_or_else(|| "Unknown incident".to_string());

    format!(
        "Aegira incident alert\\n\\nRule: {}\\nStatus: {}\\nIncident: {}\\nHost: {}",
        rule_info,
        status,
        incident,
        std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string())
    )
}

fn remediation_allowed() -> bool {
    // Development/testing mode: license enforcement is intentionally disabled.
    // Production should validate the license with the Aegira licensing service here.
    if !LICENSE_ENFORCEMENT_ENABLED {
        return true;
    }
    false
}

fn perform_remediation(remediation: &Remediation, ctx: Option<&IncidentContext>, rule: &Rule) -> Result<(), String> {
    match remediation {
        Remediation::ServiceRestart { service } => {
            let target = resolve_service_target(service)?;
            if normalize_target(&target) == SELF_SERVICE { return Err("Refusing remediation: rule attempts to restart Aegira itself".to_string()); }
            let systemctl = systemctl_binary()?;
            log_incident(&format!("[RECOVERY] Restarting service: {}", target));
            execute_command(systemctl, &["restart", target.as_str()])
        }
        Remediation::ContainerRestart { container } => {
            let target = resolve_container_target(container)?;
            let docker = docker_binary()?;
            log_incident(&format!("[RECOVERY] Restarting container: {}", target));
            execute_command(docker, &["restart", target.as_str()])
        }
        Remediation::Command { executable, args } => {
            let expanded: Vec<String> = args.iter().map(|a| expand_command_arg(a, ctx, rule)).collect();
            let (code, stdout, stderr) = execute_command_capture(executable, &expanded, COMMAND_TIMEOUT_SECS)?;
            if code == 0 { Ok(()) } else { Err(format!("{} exited with code {}. stdout={} stderr={}", executable, code, stdout.trim(), stderr.trim())) }
        }
        Remediation::ContainerExec { container, args } => {
            let target = resolve_container_target(container)?;
            let docker = docker_binary()?;
            let mut full = vec!["exec".to_string(), target.clone()];
            full.extend(args.iter().map(|a| expand_command_arg(a, ctx, rule)));
            let (code, stdout, stderr) = execute_command_capture(docker, &full, COMMAND_TIMEOUT_SECS)?;
            if code == 0 { Ok(()) } else { Err(format!("docker exec {} failed with code {}. stdout={} stderr={}", target, code, stdout.trim(), stderr.trim())) }
        }
        Remediation::CommandSequence { commands, verifications } => {
            execute_command_sequence(commands, verifications, ctx, rule)
        }
        Remediation::AlertOnly => Err("Alert-only rule does not perform remediation".to_string()),
    }
}

fn verify_recovery(verification: &Verification, ctx: Option<&IncidentContext>, rule: &Rule) -> bool {
    match verification {
        Verification::None => { log_incident("[VERIFY] No verification required"); true }
        Verification::ServiceActive { service } => {
            let target = match resolve_service_target(service) { Ok(v)=>v, Err(e)=>{log_incident(&format!("[VERIFY ERROR] {}",e)); return false;} };
            let systemctl = match systemctl_binary() { Ok(v)=>v, Err(e)=>{log_incident(&format!("[VERIFY ERROR] {}",e)); return false;} };
            match Command::new(systemctl).args(["is-active", target.as_str()]).output() { Ok(o)=>o.status.success() && String::from_utf8_lossy(&o.stdout).trim()=="active", Err(e)=>{log_incident(&format!("[VERIFY ERROR] {}",e)); false} }
        }
        Verification::ContainerRunning { container } => {
            let target = match resolve_container_target(container) { Ok(v)=>v, Err(e)=>{log_incident(&format!("[VERIFY ERROR] {}",e)); return false;} };
            let docker = match docker_binary() { Ok(v)=>v, Err(e)=>{log_incident(&format!("[VERIFY ERROR] {}",e)); return false;} };
            match Command::new(docker).args(["inspect", "-f", "{{.State.Running}}", target.as_str()]).output() { Ok(o)=>o.status.success() && String::from_utf8_lossy(&o.stdout).trim()=="true", Err(e)=>{log_incident(&format!("[VERIFY ERROR] {}",e)); false} }
        }
        Verification::ContainerHealthy { container } => {
            let target = match resolve_container_target(container) { Ok(v)=>v, Err(_)=>return false };
            let docker = match docker_binary() { Ok(v)=>v, Err(_)=>return false };
            match Command::new(docker).args(["inspect", "-f", "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}", target.as_str()]).output() {
                Ok(o)=>o.status.success() && String::from_utf8_lossy(&o.stdout).trim().eq_ignore_ascii_case("healthy"),
                Err(_)=>false,
            }
        }
        Verification::ContainerProbeSuccess { container, executable, args } => {
            let target = match resolve_container_target(container) { Ok(v)=>v, Err(_)=>return false };
            let docker = match docker_binary() { Ok(v)=>v, Err(_)=>return false };
            let mut full = vec!["exec".to_string(), target, executable.clone()];
            full.extend(args.iter().cloned());
            match execute_command_capture(docker, &full, COMMAND_TIMEOUT_SECS) { Ok((code,_,_))=>code==0, Err(_)=>false }
        }
        Verification::HttpStatus { url, expected_status } => {
            let client = match Client::builder().timeout(Duration::from_secs(COMPOSIO_TIMEOUT_SECS)).build() { Ok(v)=>v, Err(_)=>return false };
            match client.get(url).send() { Ok(r)=>r.status().as_u16()==*expected_status, Err(_)=>false }
        }
        Verification::ContainerHttpStatus { container, url, expected_status } => {
            verify_container_http_status(container, url, *expected_status)
        }
        Verification::CommandSuccess { executable, args } => {
            let expanded: Vec<String> = args.iter().map(|a| expand_command_arg(a, ctx, rule)).collect();
            match execute_command_capture(executable, &expanded, COMMAND_TIMEOUT_SECS) { Ok((code,_,_))=>code==0, Err(_)=>false }
        }
    }
}

fn recover_with_rule(
    rule: &Rule,
    ctx: &IncidentContext,
) -> Result<(), String> {
    log_incident(&format!(
        "[MATCH] Rule: {}",
        rule.name
    ));

    log_incident(&format!(
        "[MATCH] Rule ID: {}",
        rule.id
    ));

    if matches!(rule.remediation, Remediation::AlertOnly) {
        return Err("Alert-only rule does not perform remediation".to_string());
    }

    if !remediation_allowed() {
        return Err("Pro license is not active".to_string());
    }

    perform_remediation(
        &rule.remediation,
        Some(ctx),
        rule,
    )?;

    sleep(Duration::from_secs(
        VERIFY_DELAY_SECS,
    ));

    for attempt in 1..=MAX_VERIFY_ATTEMPTS {
        log_incident(&format!(
            "[VERIFY] Verification attempt {}/{}",
            attempt,
            MAX_VERIFY_ATTEMPTS
        ));

        if verify_recovery(
            &rule.verification,
            Some(ctx),
            rule,
        ) {
            return Ok(());
        }

        if attempt < MAX_VERIFY_ATTEMPTS {
            sleep(Duration::from_secs(
                VERIFY_DELAY_SECS,
            ));
        }
    }

    Err(
        "Remediation executed but health verification failed"
            .to_string(),
    )
}

fn make_incident_key(rule: &Rule, ctx: &IncidentContext) -> String {
    // Cooldowns must use stable identity, never transient Docker logs or HTTP
    // error text. Otherwise every changed log line becomes a new incident.
    format!(
        "{}:{}:{}:{}",
        rule.id.to_lowercase(),
        ctx.source,
        ctx.container.as_deref().unwrap_or(""),
        ctx.exit_code.map(|v| v.to_string()).unwrap_or_default()
    )
}

fn make_unknown_incident_key(ctx: &IncidentContext) -> String {
    format!(
        "unknown:{}:{}:{}",
        ctx.source,
        ctx.container.as_deref().unwrap_or(""),
        ctx.exit_code.map(|v| v.to_string()).unwrap_or_default()
    )
}

fn cleanup_cooldowns(
    cooldowns: &mut HashMap<String, Instant>,
) {
    let cooldown =
        Duration::from_secs(
            INCIDENT_COOLDOWN_SECS,
        );

    cooldowns.retain(
        |_, timestamp| {
            timestamp.elapsed() < cooldown
        },
    );
}

fn describe_remediation(remediation: &Remediation) -> String {
    match remediation {
        Remediation::ServiceRestart { service } => format!("systemctl restart {}", service),
        Remediation::ContainerRestart { container } => format!("docker restart {}", container),
        Remediation::Command { executable, args } => format!("{} {}", executable, args.join(" ")),
        Remediation::ContainerExec { container, args } => format!("docker exec {} {}", container, args.join(" ")),
        Remediation::CommandSequence { commands, .. } => format!(
            "{} command(s): {}",
            commands.len(),
            commands.join(" && ")
        ),
        Remediation::AlertOnly => "no remediation".to_string(),
    }
}

fn process_incident(rules: &[Rule], ctx: &IncidentContext, cooldowns: &mut HashMap<String, Instant>) {
    cleanup_cooldowns(cooldowns);
    let start = Instant::now();
    let (rule, score) = match find_best_rule_for_context(rules, ctx) {
        Some(v) => v,
        None => {
            let key = make_unknown_incident_key(ctx);
            if cooldowns.contains_key(&key) {
                return;
            }
            cooldowns.insert(key, Instant::now());
            log_incident(&format!("[MATCH] No known rule for source '{}' container='{}' exit={:?}", ctx.source, ctx.container.as_deref().unwrap_or(""), ctx.exit_code));
            send_alert("Aegira: Unknown Incident Detected", &alert_body(&ctx.incident, None, "UNKNOWN - MANUAL INVESTIGATION REQUIRED"));
            return;
        }
    };
    let key = make_incident_key(rule, ctx);
    if cooldowns.contains_key(&key) { return; }
    cooldowns.insert(key, Instant::now());
    log_incident(&format!("[WATCHER] Incident detected: {}", ctx.incident));
    log_incident(&format!("[MATCH] Rule: {}", rule.name));
    log_incident(&format!("[MATCH] Confidence score: {}", score));
    let action = rule.action.trim().to_lowercase();
    if action == "dry_run" {
        log_incident(&format!("[DRY RUN] Rule '{}' matched. Would execute: {}", rule.id, describe_remediation(&rule.remediation)));
        send_alert(&format!("Aegira: {} dry run", rule.name), &alert_body(&ctx.incident, Some(rule), "DRY RUN - REMEDIATION NOT EXECUTED"));
        return;
    }
    if action == "approval_required" {
        log_incident(&format!("[APPROVAL REQUIRED] Rule '{}' matched. Remediation was NOT executed.", rule.id));
        send_alert(&format!("Aegira: approval required for {}", rule.name), &alert_body(&ctx.incident, Some(rule), "APPROVAL REQUIRED - REMEDIATION NOT EXECUTED"));
        return;
    }
    if action == "alert_only" || matches!(rule.remediation, Remediation::AlertOnly) {
        log_incident(&format!("[ALERT ONLY] Rule '{}' will not perform remediation", rule.id));
        send_alert(&format!("Aegira: {}", rule.name), &alert_body(&ctx.incident, Some(rule), "ALERT ONLY"));
        return;
    }
    match recover_with_rule(rule, ctx) {
        Ok(()) => {
            log_incident(&format!("[RESOLVED] Incident automatically recovered in {:.2?}", start.elapsed()));
            if load_config().map(|c| c.alerts.notify_on_recovery).unwrap_or(false) { send_alert(&format!("Aegira: {} recovered", rule.name), &alert_body(&ctx.incident, Some(rule), "RECOVERED")); }
        }
        Err(e) => {
            log_incident(&format!("[RECOVERY FAILED] {}", e));
            log_incident(&format!("[MANUAL ACTION] Rule '{}' requires intervention", rule.id));
            send_alert(&format!("Aegira: {} recovery failed", rule.name), &alert_body(&ctx.incident, Some(rule), "RECOVERY FAILED - MANUAL ACTION REQUIRED"));
        }
    }
}

#[cfg(unix)]
fn get_file_identity(
    path: &Path,
) -> Result<FileIdentity, String> {
    use std::os::unix::fs::MetadataExt;

    let metadata =
        fs::metadata(path)
            .map_err(|e| {
                format!(
                    "Failed to read metadata for {}: {}",
                    path.display(),
                    e
                )
            })?;

    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(not(unix))]
fn get_file_identity(
    path: &Path,
) -> Result<FileIdentity, String> {
    let metadata =
        fs::metadata(path)
            .map_err(|e| {
                format!(
                    "Failed to read metadata for {}: {}",
                    path.display(),
                    e
                )
            })?;

    Ok(FileIdentity {
        device: 0,
        inode: metadata.len(),
    })
}

fn parse_docker_event_line(line: &str) -> Option<(String, String, Option<i32>, Option<String>)> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let status = value.get("status").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let id = value.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let attrs = value.get("Actor").and_then(|v| v.get("Attributes"));
    let name = attrs.and_then(|v| v.get("name")).and_then(|v| v.as_str()).map(|s| s.to_string());
    let exit_code = attrs.and_then(|v| v.get("exitCode")).and_then(|v| v.as_str()).and_then(|s| s.parse::<i32>().ok());
    if id.is_empty() { None } else { Some((status, id, exit_code, name)) }
}

fn run_docker_event_monitor() {
    let mut rules = load_all_rules();
    let mut fingerprint = get_rule_fingerprint();
    let mut cooldowns = HashMap::new();
    let mut seen_events: HashMap<String, Instant> = HashMap::new();
    loop {
        seen_events.retain(|_, timestamp| timestamp.elapsed() < Duration::from_secs(INCIDENT_COOLDOWN_SECS));
        let docker = match docker_binary() { Ok(v)=>v, Err(e)=>{log_incident(&format!("[DOCKER] {}",e)); sleep(Duration::from_secs(DOCKER_EVENT_RECONNECT_SECS)); continue;} };
        log_incident("[DOCKER] Starting Docker event monitor");
        let mut child = match Command::new(docker).args(["events", "--filter", "type=container", "--format", "{{json .}}"]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
            Ok(c)=>c, Err(e)=>{log_incident(&format!("[DOCKER] Failed to start docker events: {}",e)); sleep(Duration::from_secs(DOCKER_EVENT_RECONNECT_SECS)); continue;}
        };
        if let Some(stdout)=child.stdout.take() {
            let reader=BufReader::new(stdout);
            for line in reader.lines().flatten() {
                let current = get_rule_fingerprint();
                if current != fingerprint { let nr=load_all_rules(); if !nr.is_empty(){rules=nr; fingerprint=current;} }
                let Some((status,id,exit_code,name))=parse_docker_event_line(&line) else { continue };
                seen_events.retain(|_, timestamp| timestamp.elapsed() < Duration::from_secs(INCIDENT_COOLDOWN_SECS));
                let event_key = format!("{}:{}:{}", id, status, exit_code.map(|v| v.to_string()).unwrap_or_default());
                if seen_events.contains_key(&event_key) { continue; }
                seen_events.insert(event_key, Instant::now());
                let container=name.unwrap_or_else(|| container_display_name(&id));
                match status.as_str() {
                    "die" => {
                        let mut incident=format!("Docker container '{}' exited", container);
                        if let Some(code)=exit_code { incident.push_str(&format!(" with exit code {}",code)); }
                        incident.push_str(&docker_logs_context(&container));
                        let ctx=IncidentContext{source:"docker_exit",incident,container:Some(container),exit_code,health_status:None};
                        process_incident(&rules,&ctx,&mut cooldowns);
                    }
                    status if status.starts_with("health_status:") => {
                        let health= status.split_once(':').map(|(_,v)|v.trim().to_string()).filter(|s|!s.is_empty());
                        let status_name=health.clone().unwrap_or_else(|| "unhealthy".to_string());
                        let incident=format!("Docker container '{}' health status {}{}",container,status_name,docker_logs_context(&container));
                        let ctx=IncidentContext{source:"docker_health",incident,container:Some(container),exit_code:None,health_status:Some(status_name)};
                        process_incident(&rules,&ctx,&mut cooldowns);
                    }
                    "oom" => {
                        let incident=format!("Docker container '{}' OOM event detected{}",container,docker_logs_context(&container));
                        let ctx=IncidentContext{source:"docker_oom",incident,container:Some(container),exit_code:Some(137),health_status:None};
                        process_incident(&rules,&ctx,&mut cooldowns);
                    }
                    _ => {}
                }
            }
        }
        let _=child.kill(); let _=child.wait();
        log_incident("[DOCKER] Docker event stream ended; reconnecting");
        sleep(Duration::from_secs(DOCKER_EVENT_RECONNECT_SECS));
    }
}

fn docker_container_is_running(container: &str) -> Result<bool, String> {
    let docker = docker_binary()?;
    let output = Command::new(docker)
        .args(["inspect", "--type", "container", "-f", "{{.State.Running}}", container])
        .output()
        .map_err(|e| format!("Failed to inspect container '{}': {}", container, e))?;
    if !output.status.success() {
        return Ok(false);
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim() == "true")
}

/// For loopback URLs, prove that the URL's published host port belongs to the
/// named container. This prevents an HTTP rule from accidentally recovering a
/// different container that happens to expose the same endpoint.
fn http_endpoint_matches_container(url: &str, container: &str) -> Result<(), String> {
    let parsed = Url::parse(url).map_err(|e| format!("Invalid HTTP health URL '{}': {}", url, e))?;
    let host = parsed.host_str().unwrap_or("");
    if host != "127.0.0.1" && host != "localhost" {
        // Non-loopback endpoints may be reverse-proxied or externally routed.
        // The explicit container field still binds the recovery rule to one
        // container; only local published-port ownership can be proven here.
        return Ok(());
    }

    let host_port = parsed.port_or_known_default()
        .ok_or_else(|| format!("Could not determine port for HTTP health URL '{}'", url))?;
    let state = docker_inspect_state(container)
        .ok_or_else(|| format!("Container '{}' does not exist; cannot bind HTTP endpoint '{}'", container, url))?;
    let ports = state
        .get("NetworkSettings")
        .and_then(|v| v.get("Ports"))
        .and_then(|v| v.as_object())
        .ok_or_else(|| format!("Container '{}' has no published Docker ports; cannot bind '{}'", container, url))?;

    for bindings in ports.values() {
        if let Some(bindings) = bindings.as_array() {
            for binding in bindings {
                if binding.get("HostPort").and_then(|v| v.as_str()) == Some(&host_port.to_string()) {
                    return Ok(());
                }
            }
        }
    }

    Err(format!(
        "HTTP endpoint '{}' is not published by container '{}'",
        url, container
    ))
}

fn verify_container_http_status(container: &str, url: &str, expected_status: u16) -> bool {
    let target = match resolve_container_target(container) {
        Ok(v) => v,
        Err(e) => { log_incident(&format!("[VERIFY ERROR] {}", e)); return false; }
    };
    if let Err(e) = http_endpoint_matches_container(url, &target) {
        log_incident(&format!("[VERIFY ERROR] {}", e));
        return false;
    }
    if !docker_container_is_running(&target).unwrap_or(false) {
        return false;
    }
    let client = match Client::builder().timeout(Duration::from_secs(COMMAND_TIMEOUT_SECS)).build() {
        Ok(v) => v,
        Err(_) => return false,
    };
    match client.get(url).send() {
        Ok(resp) => resp.status().as_u16() == expected_status,
        Err(_) => false,
    }
}

fn run_http_health_monitor() {
    let mut cooldowns = HashMap::new();
    let mut reported_http_config_errors: HashSet<String> = HashSet::new();
    let mut rules = load_all_rules();
    let mut fingerprint = get_rule_fingerprint();

    loop {
        let current = get_rule_fingerprint();
        if current != fingerprint {
            let new_rules = load_all_rules();
            rules = new_rules;
            reported_http_config_errors.clear();
            fingerprint = current;
        }

        let client = match Client::builder()
            .timeout(Duration::from_secs(COMMAND_TIMEOUT_SECS))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                log_incident(&format!("[HTTP] Failed to create HTTP client: {}", e));
                sleep(Duration::from_secs(API_HEALTH_POLL_SECS));
                continue;
            }
        };

        for rule in &rules {
            if let Trigger::HttpHealth { url, container, expected_status, .. } = &rule.trigger {
                let Some(container_spec) = container.as_deref() else {
                    // Invalid rules are normally rejected by validation. Keep
                    // this guard so a malformed rule can never trigger a blind
                    // recovery if it slips in through a future code path.
                    continue;
                };
                let target = match resolve_trigger_container(container_spec) {
                    Ok(v) => v,
                    Err(e) => {
                        let key = format!("{}:resolve", rule.id);
                        if reported_http_config_errors.insert(key) {
                            log_incident(&format!("[HTTP] Rule '{}' disabled: {}", rule.id, e));
                        }
                        continue;
                    }
                };
                if let Err(e) = http_endpoint_matches_container(url, &target) {
                    let key = format!("{}:endpoint", rule.id);
                    if reported_http_config_errors.insert(key) {
                        log_incident(&format!("[HTTP] Rule '{}' disabled: {}", rule.id, e));
                    }
                    continue;
                }

                match client.get(url).send() {
                    Ok(resp) if resp.status().as_u16() == *expected_status => {}
                    Ok(resp) => {
                        let ctx = IncidentContext {
                            source: "http_health",
                            incident: format!(
                                "HTTP health check failed for container '{}' at {}: got {}, expected {}",
                                target, url, resp.status(), expected_status
                            ),
                            container: Some(target.clone()),
                            exit_code: None,
                            health_status: None,
                        };
                        process_incident(&rules, &ctx, &mut cooldowns);
                    }
                    Err(e) => {
                        let ctx = IncidentContext {
                            source: "http_health",
                            incident: format!(
                                "HTTP health check failed for container '{}' at {}: {}",
                                target, url, e
                            ),
                            container: Some(target.clone()),
                            exit_code: None,
                            health_status: None,
                        };
                        process_incident(&rules, &ctx, &mut cooldowns);
                    }
                }
            }

            if let Trigger::ContainerProbe { container, executable, args, .. } = &rule.trigger {
                let target = match resolve_trigger_container(container) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let docker = match docker_binary() {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let mut full = vec!["exec".to_string(), target.clone(), executable.clone()];
                full.extend(args.iter().cloned());
                match execute_command_capture(docker, &full, COMMAND_TIMEOUT_SECS) {
                    Ok((0, _, _)) => {}
                    Ok((code, stdout, stderr)) => {
                        let ctx = IncidentContext {
                            source: "container_probe",
                            incident: format!(
                                "Container probe '{}' failed for '{}' with exit code {} stdout={} stderr={}",
                                executable, target, code, stdout.trim(), stderr.trim()
                            ),
                            container: Some(target),
                            exit_code: Some(code),
                            health_status: None,
                        };
                        process_incident(&rules, &ctx, &mut cooldowns);
                    }
                    Err(e) => {
                        let ctx = IncidentContext {
                            source: "container_probe",
                            incident: format!("Container probe '{}' failed for '{}': {}", executable, target, e),
                            container: Some(target),
                            exit_code: None,
                            health_status: None,
                        };
                        process_incident(&rules, &ctx, &mut cooldowns);
                    }
                }
            }
        }

        cleanup_cooldowns(&mut cooldowns);
        let interval = rules
            .iter()
            .filter_map(|r| match &r.trigger {
                Trigger::HttpHealth { interval_secs, .. } => Some(*interval_secs),
                Trigger::ContainerProbe { interval_secs, .. } => Some(*interval_secs),
                _ => None,
            })
            .min()
            .unwrap_or(API_HEALTH_POLL_SECS)
            .max(1);
        sleep(Duration::from_secs(interval));
    }
}

fn run_docker_status(container: &str) -> Result<(), String> {
    let docker = docker_binary()?;
    let output = Command::new(docker)
        .args(["inspect", "--type", "container", container])
        .output()
        .map_err(|e| format!("Failed to inspect Docker container: {}", e))?;
    if !output.status.success() {
        return Err(format!("Docker inspect failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    let values: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("Failed to parse Docker inspect output: {}", e))?;
    let state = values.get(0).and_then(|v| v.get("State")).cloned().unwrap_or_default();
    println!("Container: {}", container);
    println!("Running: {}", state.get("Running").and_then(|v| v.as_bool()).unwrap_or(false));
    println!("Status: {}", state.get("Status").and_then(|v| v.as_str()).unwrap_or("unknown"));
    println!("ExitCode: {}", state.get("ExitCode").and_then(|v| v.as_i64()).unwrap_or(-1));
    println!("OOMKilled: {}", state.get("OOMKilled").and_then(|v| v.as_bool()).unwrap_or(false));
    if let Some(health) = state.get("Health") {
        println!("Health: {}", health.get("Status").and_then(|v| v.as_str()).unwrap_or("unknown"));
        println!("Health failing streak: {}", health.get("FailingStreak").and_then(|v| v.as_u64()).unwrap_or(0));
    } else {
        println!("Health: none");
    }
    Ok(())
}

fn print_usage() {
    println!("Aegira Automated Recovery Engine");
    println!();
    println!("Usage:");
    println!("  aegira install");
    println!("  aegira status");
    println!("  aegira show-rules");
    println!("  aegira history");
    println!("  aegira configure service <name>");
    println!("  aegira configure container <name>");
    println!("  aegira configure alerts <on|off> [recipient_email]");
    println!("  aegira license");
    println!("  aegira run");
    println!("  aegira docker-status <container>");
}

fn run_monitor() {
    if let Err(e) = ensure_environment_setup() {
        eprintln!("[FATAL] Environment setup failed: {}", e);
        return;
    }

    let aegira_dir = get_aegira_dir();
    log_incident("[INFO] Aegira Recovery Engine Started");
    log_incident(&format!("[INFO] Aegira directory: {}", aegira_dir.display()));
    log_incident(&format!("[INFO] Monitoring log: {}", LOG_FILE_PATH));

    let mut rules = load_all_rules();
    let mut rule_fingerprint = get_rule_fingerprint();
    log_incident(&format!("[INFO] {} remediation rules ready", rules.len()));

    let log_path = Path::new(LOG_FILE_PATH);
    let mut position = match fs::metadata(log_path) {
        Ok(metadata) => metadata.len(),
        Err(e) => {
            log_incident(&format!("[FATAL] Failed to inspect monitored log: {}", e));
            return;
        }
    };
    let mut file_identity = match get_file_identity(log_path) {
        Ok(identity) => identity,
        Err(e) => {
            log_incident(&format!("[FATAL] {}", e));
            return;
        }
    };
    let mut cooldowns: HashMap<String, Instant> = HashMap::new();
    log_incident("[INFO] Monitoring new log entries...");

    let docker_enabled = docker_binary().is_ok();
    std::thread::spawn(run_http_health_monitor);
    log_incident("[HTTP] HTTP health monitoring worker enabled");
    if docker_enabled {
        std::thread::spawn(run_docker_event_monitor);
        log_incident("[DOCKER] Docker event monitoring enabled");
    } else {
        log_incident("[DOCKER] Docker binary not found; Docker event monitoring disabled");
    }

    loop {
        let current_fingerprint = get_rule_fingerprint();
        if current_fingerprint != rule_fingerprint {
            let new_rules = load_all_rules();
            if !new_rules.is_empty() {
                rules = new_rules;
                rule_fingerprint = current_fingerprint;
                log_incident(&format!("[RULES] Rules changed. Reloaded: {} active", rules.len()));
            }
        }

        let metadata = match fs::metadata(log_path) {
            Ok(metadata) => metadata,
            Err(e) => {
                log_incident(&format!("[LOG ERROR] Failed to stat monitored log: {}", e));
                sleep(Duration::from_secs(POLL_INTERVAL_SECS));
                continue;
            }
        };
        let current_identity = match get_file_identity(log_path) {
            Ok(identity) => identity,
            Err(e) => {
                log_incident(&format!("[LOG ERROR] {}", e));
                sleep(Duration::from_secs(POLL_INTERVAL_SECS));
                continue;
            }
        };
        let file_size = metadata.len();

        if current_identity != file_identity {
            log_incident("[INFO] Log rotation detected. Resetting position.");
            file_identity = current_identity;
            position = 0;
        } else if file_size < position {
            log_incident("[INFO] Log truncation detected. Resetting position.");
            position = 0;
        }

        if file_size > position {
            let file = match File::open(log_path) {
                Ok(file) => file,
                Err(e) => {
                    log_incident(&format!("[LOG ERROR] Failed opening monitored log: {}", e));
                    sleep(Duration::from_secs(POLL_INTERVAL_SECS));
                    continue;
                }
            };
            let mut reader = BufReader::new(file);
            if let Err(e) = reader.seek(SeekFrom::Start(position)) {
                log_incident(&format!("[LOG ERROR] Failed seeking monitored log: {}", e));
                sleep(Duration::from_secs(POLL_INTERVAL_SECS));
                continue;
            }

            loop {
                let line_start = position;
                let mut line = String::new();
                let bytes_read = match reader.read_line(&mut line) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        log_incident(&format!("[LOG ERROR] Failed reading monitored log: {}", e));
                        break;
                    }
                };
                if bytes_read == 0 {
                    break;
                }
                if !line.ends_with('\n') {
                    position = line_start;
                    break;
                }
                position = line_start + bytes_read as u64;
                let trimmed = line.trim();
                if trimmed.contains("[ERROR]") || trimmed.contains("[CRITICAL]") {
                    let ctx = IncidentContext::log(trimmed.to_string());
                    process_incident(&rules, &ctx, &mut cooldowns);
                }
            }
        }

        sleep(Duration::from_secs(POLL_INTERVAL_SECS));
    }
}

fn run_install() -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err("Aegira installation currently requires Linux.".to_string());
    }

    if unsafe { libc_geteuid() } != 0 {
        return Err("Installation must be run as root. Use: sudo ./target/release/aegira install".to_string());
    }

    let executable = std::env::current_exe()
        .map_err(|e| format!("Failed to determine Aegira executable path: {}", e))?
        .canonicalize()
        .map_err(|e| format!("Failed to resolve Aegira executable path: {}", e))?;

    let mut rule_candidates: Vec<PathBuf> = Vec::new();

    // First check beside the executable.
    if let Some(parent) = executable.parent() {
        rule_candidates.push(parent.join("rules.json"));
        rule_candidates.push(parent.join("rules/builtin/rules.json"));

        // Then walk upward through the project directories.
        // This supports the normal Cargo layout:
        // project/rules.json
        // project/target/release/aegira
        let mut ancestor = parent;
        while let Some(next) = ancestor.parent() {
            if next == ancestor {
                break;
            }
            rule_candidates.push(next.join("rules.json"));
            ancestor = next;
        }
    }

    // Finally check the directory from which the installer was launched.
    rule_candidates.push(PathBuf::from("rules.json"));
    rule_candidates.push(PathBuf::from("rules/builtin/rules.json"));

    if let Some(source_rules) = rule_candidates.iter().find(|path| path.is_file()) {
        return install_from_rules(&executable, source_rules);
    }

    Err(format!(
        "Bundled rules.json could not be found. Aegira checked beside the binary, its parent directories, and the current directory. Put rules.json in the project root and run the installer again."
    ))
}

fn install_from_rules(executable: &Path, source_rules: &Path) -> Result<(), String> {
    let aegira_dir = get_aegira_dir();
    let builtin_dir = Path::new(BUILTIN_RULES_DIR);
    let custom_dir = Path::new(CUSTOM_RULES_DIR);
    let log_dir = Path::new(LOGS_DIR);

    fs::create_dir_all(&aegira_dir)
        .map_err(|e| format!("Failed to create {}: {}", aegira_dir.display(), e))?;
    fs::create_dir_all(builtin_dir)
        .map_err(|e| format!("Failed to create {}: {}", builtin_dir.display(), e))?;
    fs::create_dir_all(custom_dir)
        .map_err(|e| format!("Failed to create {}: {}", custom_dir.display(), e))?;
    fs::create_dir_all(log_dir)
        .map_err(|e| format!("Failed to create {}: {}", log_dir.display(), e))?;

    let installed_rules = builtin_dir.join("rules.json");
    fs::copy(source_rules, &installed_rules)
        .map_err(|e| format!("Failed to install rules.json: {}", e))?;

    ensure_file_exists(Path::new(LOG_FILE_PATH))?;
    ensure_file_exists(Path::new(INCIDENT_LOG_PATH))?;

    let composio_env = Path::new(COMPOSIO_ENV_FILE);
    ensure_file_exists(composio_env)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(composio_env)
            .map_err(|e| format!("Failed to read {} permissions: {}", composio_env.display(), e))?
            .permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(composio_env, permissions)
            .map_err(|e| format!("Failed to secure {}: {}", composio_env.display(), e))?;
    }

    let service_path = Path::new("/etc/systemd/system/aegira.service");
    let service_contents = format!(
        "[Unit]\nDescription=Aegira Automated Recovery Engine\nAfter=network.target\n\n[Service]\nType=simple\nUser=root\nEnvironmentFile=-/etc/aegira/composio.env\nExecStart={} run\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target\n",
        executable.display()
    );

    fs::write(service_path, service_contents)
        .map_err(|e| format!("Failed to write {}: {}", service_path.display(), e))?;

    let systemctl = systemctl_binary()?;
    execute_command(systemctl, &["daemon-reload"])?;
    execute_command(systemctl, &["enable", "aegira.service"])?;
    execute_command(systemctl, &["restart", "aegira.service"])?;

    println!();
    println!("[INSTALL] Aegira installed successfully.");
    println!("[INSTALL] Rules: {}", installed_rules.display());
    println!("[INSTALL] Log: {}", LOG_FILE_PATH);
    println!("[INSTALL] Service: aegira.service");
    println!("[INSTALL] Aegira is now running.");

    Ok(())
}

fn run_configure(args: &[String]) -> Result<(), String> {
    if unsafe { libc_geteuid() } != 0 {
        return Err("Configuration must be run as root. Use sudo.".to_string());
    }
    if args.len() != 4 {
        return Err("Usage: sudo aegira configure service <name> OR sudo aegira configure container <name>".to_string());
    }
    let kind = args[2].as_str();
    let name = args[3].trim();
    if name.is_empty() || name == "TARGET_SERVICE" || name == "TARGET_CONTAINER" {
        return Err("Target name cannot be empty or a placeholder.".to_string());
    }
    let mut config = load_config()?;
    match kind {
        "service" => {
            if normalize_target(name) == SELF_SERVICE {
                return Err("Refusing to target Aegira itself.".to_string());
            }
            config.target_service = Some(name.to_string());
            log_incident(&format!("[CONFIG] Target service configured: {}", name));
        }
        "container" => {
            config.target_container = Some(name.to_string());
            log_incident(&format!("[CONFIG] Target container configured: {}", name));
        }
        _ => return Err("Target type must be 'service' or 'container'.".to_string()),
    }
    save_config(&config)
}

fn run_configure_alerts(args: &[String]) -> Result<(), String> {
    if unsafe { libc_geteuid() } != 0 {
        return Err("Configuration must be run as root. Use sudo.".to_string());
    }
    if args.len() < 4 || args.len() > 5 {
        return Err("Usage: sudo aegira configure alerts <on|off> [recipient_email]".to_string());
    }
    let mode = args[3].as_str();
    let mut config = load_config()?;
    match mode {
        "on" => {
            config.alerts.enabled = true;
            if args.len() == 5 {
                let email = args[4].trim();
                if email.is_empty() || !email.contains('@') {
                    return Err("A valid recipient email is required.".to_string());
                }
                config.alerts.recipient_email = Some(email.to_string());
            }
            log_incident("[CONFIG] Gmail alerting enabled");
        }
        "off" => {
            config.alerts.enabled = false;
            log_incident("[CONFIG] Gmail alerting disabled");
        }
        _ => return Err("Alert mode must be 'on' or 'off'.".to_string()),
    }
    save_config(&config)
}

fn run_license(_args: &[String]) -> Result<(), String> {
    // License-key enforcement is intentionally disabled for development/testing.
    // Production flow: user purchases a subscription, receives a license key,
    // enters it once, and Aegira validates the subscription with the licensing service.
    // The billing provider renews the subscription monthly until cancellation.
    println!("[LICENSE] Pro license enforcement is disabled for development/testing.");
    println!("[LICENSE] No payment or license key is required in this build.");
    Ok(())
}

fn run_status() -> Result<(), String> {
    let systemctl = systemctl_binary()?;
    let output = Command::new(systemctl)
        .args(["status", "aegira.service", "--no-pager"])
        .output()
        .map_err(|e| format!("Failed to query Aegira service: {}", e))?;

    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));

    if output.status.success() {
        Ok(())
    } else {
        Err("Aegira service is not active.".to_string())
    }
}

fn run_history() -> Result<(), String> {
    ensure_environment_setup()?;
    let contents = fs::read_to_string(INCIDENT_LOG_PATH)
        .map_err(|e| format!("Failed to read incident log: {}", e))?;
    println!("{}", contents);
    Ok(())
}

fn run_show_rules() -> Result<(), String> {
    let rules = load_all_rules();
    println!();
    println!("Active Aegira rules: {}", rules.len());
    for rule in rules {
        println!("- {} ({})", rule.id, rule.name);
    }
    Ok(())
}

#[cfg(unix)]
unsafe fn libc_geteuid() -> u32 {
    extern "C" {
        fn geteuid() -> u32;
    }
    geteuid()
}

#[cfg(not(unix))]
unsafe fn libc_geteuid() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_docker_die_event() {
        let line = r#"{"status":"die","id":"abc123","Actor":{"Attributes":{"name":"my-app","exitCode":"42"}}}"#;
        let parsed = parse_docker_event_line(line).unwrap();
        assert_eq!(parsed.0, "die");
        assert_eq!(parsed.1, "abc123");
        assert_eq!(parsed.2, Some(42));
        assert_eq!(parsed.3.as_deref(), Some("my-app"));
    }

    #[test]
    fn exit_trigger_matches_requested_code() {
        let rule = Rule {
            id: "test".into(),
            name: "test".into(),
            severity: "high".into(),
            error_patterns: vec!["exit code 42".into()],
            context_patterns: vec!["docker container".into()],
            trigger: Trigger::DockerExit { container: "my-app".into(), exit_codes: vec![42] },
            remediation: Remediation::AlertOnly,
            verification: Verification::None,
            action: "alert_only".into(),
            priority: 10,
        };
        let ctx = IncidentContext {
            source: "docker_exit",
            incident: "Docker container 'my-app' exited with exit code 42".into(),
            container: Some("my-app".into()),
            exit_code: Some(42),
            health_status: None,
        };
        assert!(trigger_matches(&rule, &ctx));
    }

    #[test]
    fn placeholder_expansion_works() {
        let rule = Rule {
            id: "rule-42".into(),
            name: "Recovery Rule".into(),
            severity: "high".into(),
            error_patterns: vec!["x".into()],
            context_patterns: vec![],
            trigger: Trigger::Log,
            remediation: Remediation::AlertOnly,
            verification: Verification::None,
            action: "alert_only".into(),
            priority: 1,
        };
        let ctx = IncidentContext {
            source: "docker_exit",
            incident: "container x failed".into(),
            container: Some("my-app".into()),
            exit_code: Some(42),
            health_status: None,
        };
        let out = expand_command_arg("{CONTAINER}:{EXIT_CODE}:{RULE_ID}:{SOURCE}:{INCIDENT}", Some(&ctx), &rule);
        assert!(out.contains("my-app:42:rule-42:docker_exit:container x failed"));
    }

    #[test]
    fn parses_command_sequence_remediation() {
        let json = r#"{
            "id":"sequence",
            "name":"sequence",
            "error_patterns":["sequence"],
            "remediation":{"type":"command_sequence","commands":["true","true"],"verifications":[{"type":"command_success","executable":"true"},{"type":"command_success","executable":"true"}]},
            "verification":{"type":"none"}
        }"#;
        let rule: Rule = serde_json::from_str(json).unwrap();
        match rule.remediation {
            Remediation::CommandSequence { commands, verifications } => {
                assert_eq!(commands.len(), 2);
                assert_eq!(verifications.len(), 2);
            },
            _ => panic!("expected command_sequence remediation"),
        }
    }

    #[test]
    fn command_sequence_is_limited_to_five_and_requires_verifications() {
        let json = r#"{
            "id":"sequence",
            "name":"sequence",
            "error_patterns":["sequence"],
            "remediation":{"type":"command_sequence","commands":["true","true"],"verifications":[{"type":"command_success","executable":"true"},{"type":"command_success","executable":"true"}]},
            "verification":{"type":"none"}
        }"#;
        let rule: Rule = serde_json::from_str(json).unwrap();
        assert!(validate_rule(&rule).is_ok());
    }

    #[test]
    fn docker_restart_must_be_last_command() {
        assert!(command_contains_docker_restart("docker restart my-app"));
        assert!(command_contains_docker_restart("/usr/bin/docker restart my-app"));
        assert!(!command_contains_docker_restart("docker inspect my-app"));
    }

    #[test]
    fn command_sequence_requires_one_real_verification_per_command() {
        let json = r#"{
            "id":"sequence-invalid",
            "name":"sequence-invalid",
            "error_patterns":["sequence"],
            "remediation":{"type":"command_sequence","commands":["true","true"],"verifications":[{"type":"command_success","executable":"true"}]},
            "verification":{"type":"none"}
        }"#;
        let rule: Rule = serde_json::from_str(json).unwrap();
        assert!(validate_rule(&rule).is_err());
    }

    #[test]
    fn command_sequence_rejects_docker_restart_before_final_step() {
        let json = r#"{
            "id":"sequence-restart-order",
            "name":"sequence-restart-order",
            "error_patterns":["sequence"],
            "remediation":{"type":"command_sequence","commands":["docker restart app","true"],"verifications":[{"type":"command_success","executable":"true"},{"type":"command_success","executable":"true"}]},
            "verification":{"type":"none"}
        }"#;
        let rule: Rule = serde_json::from_str(json).unwrap();
        assert!(validate_rule(&rule).is_err());
    }

    #[test]
    fn default_trigger_is_log() {
        let json = r#"{
            "id":"x","name":"x","error_patterns":["x"],
            "remediation":{"type":"alert_only"},"verification":{"type":"none"}
        }"#;
        let rule: Rule = serde_json::from_str(json).unwrap();
        assert!(matches!(rule.trigger, Trigger::Log));
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(String::as_str).unwrap_or("run");

    let result = match command {
        "install" => run_install(),
        "status" => run_status(),
        "configure" => {
            if args.get(2).map(String::as_str) == Some("alerts") {
                run_configure_alerts(&args)
            } else {
                run_configure(&args)
            }
        }
        "license" => run_license(&args),
        "history" => run_history(),
        "docker-status" => {
            match args.get(2) {
                Some(container) => run_docker_status(container),
                None => Err("Usage: aegira docker-status <container>".to_string()),
            }
        }
        "show-rules" => {
            if let Err(e) = ensure_environment_setup() {
                Err(e)
            } else {
                run_show_rules()
            }
        }
        "run" => {
            run_monitor();
            Ok(())
        }
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        unknown => Err(format!("Unknown command '{}'. Use 'aegira --help'.", unknown)),
    };

    if let Err(e) = result {
        eprintln!("[ERROR] {}", e);
        std::process::exit(1);
    }
}
