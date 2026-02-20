//! Active Response Tools Module
//!
//! Implements all Wazuh built-in active response commands via the Manager
//! PUT /active-response API endpoint. Only real, documented commands are
//! exposed — no simulated actions.
//!
//! Implemented (built-in Wazuh AR scripts):
//! - block_ip_address: `firewall-drop` — iptables DROP rule (data.srcip)
//! - firewalld_drop: `firewalld-drop` — firewalld rich-rule block (data.srcip)
//! - host_deny: `host-deny` — adds IP to /etc/hosts.deny (data.srcip)
//! - route_null: `route-null` — null-routes an IP (data.srcip)
//! - disable_user_account: `disable-account` — locks OS user account (data.dstuser)
//! - restart_wazuh_agent: `restart-wazuh` — restarts the Wazuh agent/manager
//!
//! All actions are logged to an in-memory action history for audit and metrics.
//!
//! References:
//! - https://documentation.wazuh.com/current/user-manual/capabilities/active-response/default-active-response-scripts.html
//! - https://documentation.wazuh.com/current/user-manual/api/reference.html

use crate::tools::{ToolModule, ToolUtils};
use chrono::Utc;
use rmcp::{
    model::{CallToolResult, Content},
    schemars, ErrorData as McpError,
};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{info, warn};
use uuid::Uuid;

// ============================================================================
// Parameter Structures
// ============================================================================

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct BlockIpParams {
    #[schemars(description = "IP address to block (e.g., 203.45.67.89)")]
    pub ip_address: String,

    #[schemars(description = "Target agent ID (optional — if omitted, applies to manager '000')")]
    pub agent_id: Option<String>,

    #[schemars(description = "Duration to block in seconds (default: 3600)")]
    pub duration_seconds: Option<u32>,

    #[schemars(description = "Reason for blocking (audit trail)")]
    pub reason: String,

    #[schemars(description = "Associated Wazuh alert ID")]
    pub alert_id: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct FirewalldDropParams {
    #[schemars(description = "IP address to block via firewalld (e.g., 203.45.67.89)")]
    pub ip_address: String,

    #[schemars(description = "Target agent ID (optional — if omitted, applies to manager '000')")]
    pub agent_id: Option<String>,

    #[schemars(description = "Reason for blocking (audit trail)")]
    pub reason: String,

    #[schemars(description = "Associated Wazuh alert ID")]
    pub alert_id: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct HostDenyParams {
    #[schemars(description = "IP address to add to /etc/hosts.deny (e.g., 203.45.67.89)")]
    pub ip_address: String,

    #[schemars(description = "Target agent ID (optional — if omitted, applies to manager '000')")]
    pub agent_id: Option<String>,

    #[schemars(description = "Reason for denying (audit trail)")]
    pub reason: String,

    #[schemars(description = "Associated Wazuh alert ID")]
    pub alert_id: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct RouteNullParams {
    #[schemars(description = "IP address to null-route (e.g., 203.45.67.89)")]
    pub ip_address: String,

    #[schemars(description = "Target agent ID (optional — if omitted, applies to manager '000')")]
    pub agent_id: Option<String>,

    #[schemars(description = "Reason for null-routing (audit trail)")]
    pub reason: String,

    #[schemars(description = "Associated Wazuh alert ID")]
    pub alert_id: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct DisableUserParams {
    #[schemars(description = "Target agent ID (e.g., '001')")]
    pub agent_id: String,

    #[schemars(description = "Username to disable")]
    pub username: String,

    #[schemars(description = "Reason for disabling account (audit trail)")]
    pub reason: String,

    #[schemars(description = "Associated Wazuh alert ID")]
    pub alert_id: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct RestartAgentParams {
    #[schemars(description = "Target agent ID to restart (e.g., '001')")]
    pub agent_id: String,

    #[schemars(description = "Reason for restarting (audit trail)")]
    pub reason: String,

    #[schemars(description = "Associated Wazuh alert ID")]
    pub alert_id: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct GetResponseHistoryParams {
    #[schemars(description = "Filter by alert ID (optional)")]
    pub alert_id: Option<String>,

    #[schemars(description = "Maximum number of results to return (default: 100)")]
    pub limit: Option<u32>,
}

// ============================================================================
// Response Action Tracking
// ============================================================================

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResponseAction {
    pub id: String,
    pub timestamp: String,
    pub alert_id: String,
    pub action_type: String,
    pub target: String,
    pub agent_id: Option<String>,
    pub status: String,
    pub reason: String,
    pub execution_result: Option<String>,
    pub error_message: Option<String>,
    pub executed_at: Option<String>,
    pub duration_ms: Option<u64>,
}

// ============================================================================
// Response Tools Implementation
// ============================================================================

#[derive(Clone)]
pub struct ResponseTools {
    action_history: Arc<Mutex<Vec<ResponseAction>>>,
    wazuh_manager_api: String,
    wazuh_api_username: String,
    wazuh_api_password: String,
    verify_ssl: bool,
}

impl ResponseTools {
    pub fn new(wazuh_manager_api: String) -> Self {
        Self {
            action_history: Arc::new(Mutex::new(Vec::new())),
            wazuh_manager_api,
            wazuh_api_username: std::env::var("WAZUH_API_USERNAME")
                .unwrap_or_else(|_| "wazuh".to_string()),
            wazuh_api_password: std::env::var("WAZUH_API_PASSWORD").unwrap_or_default(),
            verify_ssl: std::env::var("WAZUH_VERIFY_SSL")
                .ok()
                .and_then(|v| v.parse::<bool>().ok())
                .unwrap_or(false),
        }
    }

    pub async fn get_action_history_snapshot(&self) -> Vec<ResponseAction> {
        self.action_history.lock().await.clone()
    }

    // ========================================================================
    // IP-based active responses
    // ========================================================================

    /// Block an IP via the Wazuh built-in `firewall-drop` (iptables).
    pub async fn block_ip_address(
        &self,
        params: BlockIpParams,
    ) -> Result<CallToolResult, McpError> {
        if !Self::is_valid_ip(&params.ip_address) {
            return Self::error_result(format!("Invalid IP address: {}", params.ip_address));
        }
        let agent = match self.normalize_agent_opt(params.agent_id.as_deref()) {
            Ok(a) => a,
            Err(e) => return Self::error_result(e),
        };
        let payload = json!({
            "command": "!firewall-drop",
            "alert": { "data": { "srcip": params.ip_address } }
        });
        self.execute_and_record(
            "block_ip",
            &params.ip_address,
            agent.as_deref(),
            &params.alert_id,
            &params.reason,
            &payload,
        )
        .await
    }

    /// Block an IP via the Wazuh built-in `firewalld-drop` (firewalld rich-rule).
    /// Requires firewalld installed on the target agent.
    pub async fn firewalld_drop(
        &self,
        params: FirewalldDropParams,
    ) -> Result<CallToolResult, McpError> {
        if !Self::is_valid_ip(&params.ip_address) {
            return Self::error_result(format!("Invalid IP address: {}", params.ip_address));
        }
        let agent = match self.normalize_agent_opt(params.agent_id.as_deref()) {
            Ok(a) => a,
            Err(e) => return Self::error_result(e),
        };
        let payload = json!({
            "command": "!firewalld-drop",
            "alert": { "data": { "srcip": params.ip_address } }
        });
        self.execute_and_record(
            "firewalld_drop",
            &params.ip_address,
            agent.as_deref(),
            &params.alert_id,
            &params.reason,
            &payload,
        )
        .await
    }

    /// Add an IP to /etc/hosts.deny via the Wazuh built-in `host-deny`.
    pub async fn host_deny(
        &self,
        params: HostDenyParams,
    ) -> Result<CallToolResult, McpError> {
        if !Self::is_valid_ip(&params.ip_address) {
            return Self::error_result(format!("Invalid IP address: {}", params.ip_address));
        }
        let agent = match self.normalize_agent_opt(params.agent_id.as_deref()) {
            Ok(a) => a,
            Err(e) => return Self::error_result(e),
        };
        let payload = json!({
            "command": "!host-deny",
            "alert": { "data": { "srcip": params.ip_address } }
        });
        self.execute_and_record(
            "host_deny",
            &params.ip_address,
            agent.as_deref(),
            &params.alert_id,
            &params.reason,
            &payload,
        )
        .await
    }

    /// Null-route an IP via the Wazuh built-in `route-null`.
    pub async fn route_null(
        &self,
        params: RouteNullParams,
    ) -> Result<CallToolResult, McpError> {
        if !Self::is_valid_ip(&params.ip_address) {
            return Self::error_result(format!("Invalid IP address: {}", params.ip_address));
        }
        let agent = match self.normalize_agent_opt(params.agent_id.as_deref()) {
            Ok(a) => a,
            Err(e) => return Self::error_result(e),
        };
        let payload = json!({
            "command": "!route-null",
            "alert": { "data": { "srcip": params.ip_address } }
        });
        self.execute_and_record(
            "route_null",
            &params.ip_address,
            agent.as_deref(),
            &params.alert_id,
            &params.reason,
            &payload,
        )
        .await
    }

    // ========================================================================
    // Account-based active responses
    // ========================================================================

    /// Disable a user account via the Wazuh built-in `disable-account`.
    /// The script locks the OS account on the target agent.
    pub async fn disable_user_account(
        &self,
        params: DisableUserParams,
    ) -> Result<CallToolResult, McpError> {
        let agent = match self.normalize_agent_required(&params.agent_id) {
            Ok(a) => a,
            Err(e) => return Self::error_result(e),
        };
        let payload = json!({
            "command": "!disable-account",
            "alert": { "data": { "dstuser": params.username } }
        });
        self.execute_and_record(
            "disable_user",
            &params.username,
            Some(&agent),
            &params.alert_id,
            &params.reason,
            &payload,
        )
        .await
    }

    // ========================================================================
    // Agent management active responses
    // ========================================================================

    /// Restart a Wazuh agent via the built-in `restart-wazuh` AR script.
    pub async fn restart_wazuh_agent(
        &self,
        params: RestartAgentParams,
    ) -> Result<CallToolResult, McpError> {
        let agent = match self.normalize_agent_required(&params.agent_id) {
            Ok(a) => a,
            Err(e) => return Self::error_result(e),
        };
        let payload = json!({
            "command": "!restart-wazuh"
        });
        self.execute_and_record(
            "restart_agent",
            &format!("agent {}", agent),
            Some(&agent),
            &params.alert_id,
            &params.reason,
            &payload,
        )
        .await
    }

    // ========================================================================
    // Action history
    // ========================================================================

    /// Get response action history.
    pub async fn get_response_history(
        &self,
        params: GetResponseHistoryParams,
    ) -> Result<CallToolResult, McpError> {
        let history = self.action_history.lock().await;
        let limit = params.limit.unwrap_or(100) as usize;

        let filtered: Vec<_> = history
            .iter()
            .filter(|action| {
                if let Some(ref alert_id) = params.alert_id {
                    &action.alert_id == alert_id
                } else {
                    true
                }
            })
            .take(limit)
            .collect();

        let response = json!({
            "total_actions": filtered.len(),
            "actions": filtered,
        });

        Self::success_result(vec![Content::text(
            serde_json::to_string_pretty(&response).unwrap(),
        )])
    }

    // ============================================================================
    // Private: common execute + record pattern
    // ============================================================================

    /// Send an AR command via the Wazuh API and record the action in history.
    async fn execute_and_record(
        &self,
        action_type: &str,
        target: &str,
        agent_id: Option<&str>,
        alert_id: &str,
        reason: &str,
        payload: &serde_json::Value,
    ) -> Result<CallToolResult, McpError> {
        let start = std::time::Instant::now();
        let action_id = Uuid::new_v4().to_string();

        let command_name = payload
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        info!(
            "Executing active response: type={} command={} target={} agent={:?} reason={}",
            action_type, command_name, target, agent_id, reason
        );

        let result = self.send_active_response(agent_id, payload).await;
        let elapsed = start.elapsed().as_millis() as u64;

        let action = ResponseAction {
            id: action_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            alert_id: alert_id.to_string(),
            action_type: action_type.to_string(),
            target: target.to_string(),
            agent_id: agent_id.map(|s| s.to_string()),
            status: if result.is_ok() {
                "completed".to_string()
            } else {
                "failed".to_string()
            },
            reason: reason.to_string(),
            execution_result: result.clone().ok(),
            error_message: result.clone().err(),
            executed_at: Some(Utc::now().to_rfc3339()),
            duration_ms: Some(elapsed),
        };

        self.action_history.lock().await.push(action);

        match result {
            Ok(msg) => {
                let resp = json!({
                    "action_id": action_id,
                    "action_type": action_type,
                    "status": "completed",
                    "target": target,
                    "agent_id": agent_id,
                    "execution_time_ms": elapsed,
                    "message": msg,
                    "timestamp": Utc::now().to_rfc3339(),
                });
                Self::success_result(vec![Content::text(
                    serde_json::to_string_pretty(&resp).unwrap(),
                )])
            }
            Err(err) => Self::error_result(format!(
                "Active response {} failed for {}: {}",
                action_type, target, err
            )),
        }
    }

    // ============================================================================
    // Private: Wazuh Manager API communication
    // ============================================================================

    /// PUT /active-response?agents_list=<id>
    async fn send_active_response(
        &self,
        agent_id: Option<&str>,
        payload: &serde_json::Value,
    ) -> Result<String, String> {
        let command_name = payload
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        warn!(
            "Active response API call: command={} agent={:?}",
            command_name, agent_id
        );

        let base = self.wazuh_manager_api.trim_end_matches('/');
        let agent_list = agent_id.unwrap_or("000");
        let endpoint = format!("{}/active-response?agents_list={}", base, agent_list);

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(!self.verify_ssl)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .user_agent("mcp-server-wazuh/response-tools")
            .build()
            .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

        let token = self.authenticate_wazuh(&client).await?;

        let resp = client
            .put(&endpoint)
            .bearer_auth(&token)
            .json(payload)
            .send()
            .await
            .map_err(|e| format!("HTTP request failed for {}: {}", command_name, e))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| format!("Failed to read response body: {}", e))?;

        if status.is_success() {
            return Ok(format!("Wazuh API ({}) response: {}", command_name, text));
        }

        Err(format!(
            "Wazuh active-response {} failed ({}): {}",
            command_name,
            status.as_u16(),
            text
        ))
    }

    async fn authenticate_wazuh(&self, client: &reqwest::Client) -> Result<String, String> {
        if self.wazuh_api_password.is_empty() {
            return Err("WAZUH_API_PASSWORD is empty; required for active response".to_string());
        }

        let auth_endpoint = format!(
            "{}/security/user/authenticate?raw=true",
            self.wazuh_manager_api.trim_end_matches('/')
        );

        let response = client
            .get(&auth_endpoint)
            .basic_auth(&self.wazuh_api_username, Some(&self.wazuh_api_password))
            .send()
            .await
            .map_err(|e| format!("Failed to authenticate with Wazuh API: {}", e))?;

        let status = response.status();
        let token_text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format!(
                "Wazuh authentication failed ({}): {}",
                status.as_u16(),
                token_text
            ));
        }

        let token = token_text.trim().trim_matches('"').to_string();
        if token.is_empty() {
            return Err("Wazuh authentication returned empty token".to_string());
        }

        Ok(token)
    }

    fn is_valid_ip(ip: &str) -> bool {
        ip.parse::<std::net::IpAddr>().is_ok()
    }

    fn normalize_agent_required(&self, agent_id: &str) -> Result<String, String> {
        ToolUtils::format_agent_id(agent_id)
    }

    fn normalize_agent_opt(&self, agent_id: Option<&str>) -> Result<Option<String>, String> {
        match agent_id {
            Some(id) => Ok(Some(self.normalize_agent_required(id)?)),
            None => Ok(None),
        }
    }
}

impl ToolModule for ResponseTools {}
