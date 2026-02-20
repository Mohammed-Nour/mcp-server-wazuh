//
// Purpose:
//
// This Rust application implements an MCP (Model Context Protocol) server that acts as a
// bridge to a Wazuh instance. It exposes various Wazuh functionalities as tools that can
// be invoked by MCP clients (e.g., AI models, automation scripts).
//
// Architecture:
// The application follows a modular design where the main MCP server delegates to
// domain-specific tool modules, promoting separation of concerns and maintainability.
//
// Structure:
// - `main()`: Entry point of the application. Initializes logging (tracing),
//   sets up the `WazuhToolsServer`, and starts the MCP server using stdio or HTTP transport.
//
// - `WazuhToolsServer`: The core orchestrator struct that implements the `rmcp::ServerHandler` trait
//   and uses `#[tool_router]` and `#[tool_handler]` macros. It acts as a facade that delegates
//   tool calls to specialized domain modules:
//   - Holds instances of domain-specific tool modules (AgentTools, AlertTools, RuleTools, etc.)
//   - Its methods, decorated with `#[tool(...)]`, define the MCP tool interface and delegate
//     to the appropriate domain module for actual implementation
//   - Manages the lifecycle and configuration of Wazuh client connections
//
// - Domain-Specific Tool Modules (in `tools/` package):
//   - `AlertTools` (`tools/alerts.rs`): Handles alert-related operations via Wazuh Indexer
//   - `RuleTools` (`tools/rules.rs`): Manages security rule queries via Wazuh Manager API
//   - `VulnerabilityTools` (`tools/vulnerabilities.rs`): Processes vulnerability data via Wazuh Manager API
//   - `AgentTools` (`tools/agents.rs`): Handles agent management and system information queries
//   - `StatsTools` (`tools/stats.rs`): Provides logging, statistics, and cluster health monitoring
//
// Configuration:
// The server requires the following environment variables to connect to the Wazuh instance:
// - `WAZUH_API_HOST`: Hostname or IP address of the Wazuh API.
// - `WAZUH_API_PORT`: Port number for the Wazuh API (default: 55000).
// - `WAZUH_API_USERNAME`: Username for Wazuh API authentication.
// - `WAZUH_API_PASSWORD`: Password for Wazuh API authentication.
// - `WAZUH_INDEXER_HOST`: Hostname or IP address of the Wazuh Indexer.
// - `WAZUH_INDEXER_PORT`: Port number for the Wazuh Indexer API (default: 9200).
// - `WAZUH_INDEXER_USERNAME`: Username for Wazuh Indexer authentication.
// - `WAZUH_INDEXER_PASSWORD`: Password for Wazuh Indexer authentication.
// - `WAZUH_VERIFY_SSL`: Set to "true" to enable SSL certificate verification, "false" otherwise (default: false).
// - `WAZUH_TEST_PROTOCOL`: (Optional) Protocol to use for Wazuh API/Indexer connections, e.g., "http" or "https" (default: "https").
// Logging behavior is controlled by the `RUST_LOG` environment variable (e.g., `RUST_LOG=info,mcp_server_wazuh=debug`).

use clap::Parser;
use dotenv::dotenv;
#[cfg(feature = "http")]
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, Content, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo,
    },
    tool, tool_handler, tool_router,
    transport::stdio,
    ErrorData as McpError, ServerHandler, ServiceExt,
};
use std::env;
use std::fs;
use std::sync::Arc;

use serde_json::json;
use wazuh_client::WazuhClientFactory;

mod tools;
use tools::agents::{AgentTools, GetAgentPortsParams, GetAgentProcessesParams, GetAgentsParams};
use tools::alerts::{AlertTools, GetAlertSummaryParams, GetAlertsInTimeRangeParams};
use tools::rules::{GetRulesSummaryParams, RuleTools};
use tools::stats::{
    GetClusterHealthParams, GetClusterNodesParams, GetLogCollectorStatsParams,
    GetManagerErrorLogsParams, GetRemotedStatsParams, GetWeeklyStatsParams,
    SearchManagerLogsParams, StatsTools,
};
use tools::vulnerabilities::{
    GetCriticalVulnerabilitiesParams, GetVulnerabilitiesSummaryParams, VulnerabilityTools,
};
// (Webhook support removed — scheduled fetching is used instead)

// Phase 2 tools
use tools::metrics::{
    EndAnalysisParams, EndResponseParams, GetMetricsParams, MetricsTools, StartAnalysisParams,
    StartResponseParams,
};
use tools::notifications::{NotificationTools, SendActionSummaryParams, SendAnalysisReportParams};
use tools::response::{
    BlockIpParams, DisableUserParams, FirewalldDropParams, GetResponseHistoryParams,
    HostDenyParams, RestartAgentParams, ResponseTools, RouteNullParams,
};

#[derive(Parser, Debug)]
#[command(name = "mcp-server-wazuh")]
#[command(about = "Wazuh SIEM MCP Server")]
struct Args {
    /// Transport mode: stdio or http
    #[arg(long, default_value = "stdio")]
    transport: String,

    /// HTTP server bind address (only for http transport)
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// HTTP server port (only for http transport)
    #[arg(long, default_value = "8080")]
    port: u16,
}

#[derive(Clone)]
struct WazuhToolsServer {
    agent_tools: AgentTools,
    alert_tools: AlertTools,
    rule_tools: RuleTools,
    stats_tools: StatsTools,
    vulnerability_tools: VulnerabilityTools,

    // Phase 2 tools
    response_tools: ResponseTools,
    metrics_tools: MetricsTools,
    notification_tools: NotificationTools,

    tool_router: ToolRouter<Self>,
}

impl WazuhToolsServer {
    fn new() -> Result<Self, anyhow::Error> {
        dotenv().ok();

        let api_host = env::var("WAZUH_API_HOST").unwrap_or_else(|_| "localhost".to_string());
        let api_port: u16 = env::var("WAZUH_API_PORT")
            .unwrap_or_else(|_| "55000".to_string())
            .parse()
            .unwrap_or(55000);
        let api_username = env::var("WAZUH_API_USERNAME").unwrap_or_else(|_| "wazuh".to_string());
        let api_password = env::var("WAZUH_API_PASSWORD").unwrap_or_else(|_| "wazuh".to_string());

        let indexer_host =
            env::var("WAZUH_INDEXER_HOST").unwrap_or_else(|_| "localhost".to_string());
        let indexer_port: u16 = env::var("WAZUH_INDEXER_PORT")
            .unwrap_or_else(|_| "9200".to_string())
            .parse()
            .unwrap_or(9200);
        let indexer_username =
            env::var("WAZUH_INDEXER_USERNAME").unwrap_or_else(|_| "admin".to_string());
        let indexer_password =
            env::var("WAZUH_INDEXER_PASSWORD").unwrap_or_else(|_| "admin".to_string());

        let verify_ssl = env::var("WAZUH_VERIFY_SSL")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false);

        let test_protocol = env::var("WAZUH_TEST_PROTOCOL")
            .ok()
            .or_else(|| Some("https".to_string()));

        let mut builder = WazuhClientFactory::builder()
            .api_host(api_host)
            .api_port(api_port)
            .api_credentials(&api_username, &api_password)
            .indexer_host(indexer_host)
            .indexer_port(indexer_port)
            .indexer_credentials(&indexer_username, &indexer_password)
            .verify_ssl(verify_ssl);

        if let Some(protocol) = test_protocol {
            builder = builder.protocol(protocol);
        }

        let wazuh_factory = builder.build();

        let wazuh_indexer_client = wazuh_factory.create_indexer_client();
        let wazuh_rules_client = wazuh_factory.create_rules_client();
        let wazuh_vulnerability_client = wazuh_factory.create_vulnerability_client();
        let wazuh_agents_client = wazuh_factory.create_agents_client();
        let wazuh_logs_client = wazuh_factory.create_logs_client();
        let wazuh_cluster_client = wazuh_factory.create_cluster_client();

        let indexer_client_arc = Arc::new(wazuh_indexer_client);
        let rules_client_arc = Arc::new(tokio::sync::Mutex::new(wazuh_rules_client));
        let vulnerability_client_arc =
            Arc::new(tokio::sync::Mutex::new(wazuh_vulnerability_client));
        let agents_client_arc = Arc::new(tokio::sync::Mutex::new(wazuh_agents_client));
        let logs_client_arc = Arc::new(tokio::sync::Mutex::new(wazuh_logs_client));
        let cluster_client_arc = Arc::new(tokio::sync::Mutex::new(wazuh_cluster_client));

        let agent_tools =
            AgentTools::new(agents_client_arc.clone(), vulnerability_client_arc.clone());
        let alert_tools = AlertTools::new(indexer_client_arc.clone());
        let rule_tools = RuleTools::new(rules_client_arc.clone());
        let stats_tools = StatsTools::new(logs_client_arc.clone(), cluster_client_arc.clone());
        let vulnerability_tools = VulnerabilityTools::new(vulnerability_client_arc.clone());

        // Initialize Phase 2 tools
        // Important: Use the same protocol configuration as the other Wazuh clients.
        let protocol = env::var("WAZUH_TEST_PROTOCOL").unwrap_or_else(|_| "https".to_string());
        let wazuh_manager_api = format!(
            "{}://{}:{}",
            protocol,
            env::var("WAZUH_API_HOST").unwrap_or_else(|_| "localhost".to_string()),
            env::var("WAZUH_API_PORT").unwrap_or_else(|_| "55000".to_string())
        );
        let response_tools = ResponseTools::new(wazuh_manager_api);
        let metrics_tools = MetricsTools::new();
        let notification_tools = NotificationTools::new();

        Ok(Self {
            agent_tools,
            alert_tools,
            rule_tools,
            stats_tools,
            vulnerability_tools,
            response_tools,
            metrics_tools,
            notification_tools,
            tool_router: Self::tool_router(),
        }) // Fixed struct
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct GenerateSocFinalReportParams {
    #[schemars(description = "Recipient email (default: WAZUH_ADMIN_EMAIL)")]
    pub recipient: Option<String>,

    #[schemars(description = "Optional report subject")]
    pub subject: Option<String>,

    #[schemars(description = "Metrics lookback period in hours (default: 24)")]
    pub period_hours: Option<u32>,

    #[schemars(description = "Optional additional analyst notes")]
    pub analyst_notes: Option<String>,
}

#[tool_router]
impl WazuhToolsServer {
    #[tool(
        name = "get_wazuh_alert_summary",
        description = "Retrieves a summary of Wazuh security alerts. Returns formatted alert information including ID, timestamp, and description."
    )]
    async fn get_wazuh_alert_summary(
        &self,
        Parameters(params): Parameters<GetAlertSummaryParams>,
    ) -> Result<CallToolResult, McpError> {
        self.alert_tools.get_wazuh_alert_summary(params).await
    }

    #[tool(
        name = "get_wazuh_alerts_in_time_range",
        description = "Retrieves Wazuh alerts within a specific timestamp range (inclusive). Useful to analyze existing alerts between two timestamps without any scheduler."
    )]
    async fn get_wazuh_alerts_in_time_range(
        &self,
        Parameters(params): Parameters<GetAlertsInTimeRangeParams>,
    ) -> Result<CallToolResult, McpError> {
        self.alert_tools
            .get_wazuh_alerts_in_time_range(params)
            .await
    }

    #[tool(
        name = "get_wazuh_rules_summary",
        description = "Retrieves a summary of Wazuh security rules. Returns formatted rule information including ID, level, description, and groups. Supports filtering by level, group, and filename."
    )]
    async fn get_wazuh_rules_summary(
        &self,
        Parameters(params): Parameters<GetRulesSummaryParams>,
    ) -> Result<CallToolResult, McpError> {
        self.rule_tools.get_wazuh_rules_summary(params).await
    }

    #[tool(
        name = "get_wazuh_vulnerability_summary",
        description = "Retrieves a summary of Wazuh vulnerability detections for a specific agent. Returns formatted vulnerability information including CVE ID, severity, detection time, and agent details. Supports filtering by severity level."
    )]
    async fn get_wazuh_vulnerability_summary(
        &self,
        Parameters(params): Parameters<GetVulnerabilitiesSummaryParams>,
    ) -> Result<CallToolResult, McpError> {
        self.vulnerability_tools
            .get_wazuh_vulnerability_summary(params)
            .await
    }

    #[tool(
        name = "get_wazuh_critical_vulnerabilities",
        description = "Retrieves critical vulnerabilities for a specific Wazuh agent. Returns formatted vulnerability information including CVE ID, title, description, CVSS scores, and detection details. Only shows vulnerabilities with 'Critical' severity level."
    )]
    async fn get_wazuh_critical_vulnerabilities(
        &self,
        Parameters(params): Parameters<GetCriticalVulnerabilitiesParams>,
    ) -> Result<CallToolResult, McpError> {
        self.vulnerability_tools
            .get_wazuh_critical_vulnerabilities(params)
            .await
    }

    #[tool(
        name = "get_wazuh_agents",
        description = "Retrieves a list of Wazuh agents with their current status and details. Returns formatted agent information including ID, name, IP, status, OS details, and last activity. Supports filtering by status, name, IP, group, OS platform, and version."
    )]
    async fn get_wazuh_agents(
        &self,
        Parameters(params): Parameters<GetAgentsParams>,
    ) -> Result<CallToolResult, McpError> {
        self.agent_tools.get_wazuh_agents(params).await
    }

    #[tool(
        name = "get_wazuh_agent_processes",
        description = "Retrieves a list of running processes for a specific Wazuh agent. Returns formatted process information including PID, name, state, user, and command. Supports filtering by process name/command."
    )]
    async fn get_wazuh_agent_processes(
        &self,
        Parameters(params): Parameters<GetAgentProcessesParams>,
    ) -> Result<CallToolResult, McpError> {
        self.agent_tools.get_wazuh_agent_processes(params).await
    }

    #[tool(
        name = "get_wazuh_cluster_health",
        description = "Checks the health of the Wazuh cluster. Returns whether the cluster is enabled, running, and if nodes are connected."
    )]
    async fn get_wazuh_cluster_health(
        &self,
        Parameters(params): Parameters<GetClusterHealthParams>,
    ) -> Result<CallToolResult, McpError> {
        self.stats_tools.get_wazuh_cluster_health(params).await
    }

    #[tool(
        name = "get_wazuh_cluster_nodes",
        description = "Retrieves a list of nodes in the Wazuh cluster. Returns formatted node information including name, type, version, IP, and status. Supports filtering by limit, offset, and node type."
    )]
    async fn get_wazuh_cluster_nodes(
        &self,
        Parameters(params): Parameters<GetClusterNodesParams>,
    ) -> Result<CallToolResult, McpError> {
        self.stats_tools.get_wazuh_cluster_nodes(params).await
    }

    #[tool(
        name = "search_wazuh_manager_logs",
        description = "Searches Wazuh manager logs. Returns formatted log entries including timestamp, tag, level, and description. Supports filtering by limit, offset, level, tag, and a search term."
    )]
    async fn search_wazuh_manager_logs(
        &self,
        Parameters(params): Parameters<SearchManagerLogsParams>,
    ) -> Result<CallToolResult, McpError> {
        self.stats_tools.search_wazuh_manager_logs(params).await
    }

    #[tool(
        name = "get_wazuh_manager_error_logs",
        description = "Retrieves Wazuh manager error logs. Returns formatted log entries including timestamp, tag, level (error), and description."
    )]
    async fn get_wazuh_manager_error_logs(
        &self,
        Parameters(params): Parameters<GetManagerErrorLogsParams>,
    ) -> Result<CallToolResult, McpError> {
        self.stats_tools.get_wazuh_manager_error_logs(params).await
    }

    #[tool(
        name = "get_wazuh_log_collector_stats",
        description = "Retrieves log collector statistics for a specific Wazuh agent. Returns information about events processed, dropped, bytes, and target log files."
    )]
    async fn get_wazuh_log_collector_stats(
        &self,
        Parameters(params): Parameters<GetLogCollectorStatsParams>,
    ) -> Result<CallToolResult, McpError> {
        self.stats_tools.get_wazuh_log_collector_stats(params).await
    }

    #[tool(
        name = "get_wazuh_remoted_stats",
        description = "Retrieves statistics from the Wazuh remoted daemon. Returns information about queue size, TCP sessions, event counts, and message traffic."
    )]
    async fn get_wazuh_remoted_stats(
        &self,
        Parameters(params): Parameters<GetRemotedStatsParams>,
    ) -> Result<CallToolResult, McpError> {
        self.stats_tools.get_wazuh_remoted_stats(params).await
    }

    #[tool(
        name = "get_wazuh_agent_ports",
        description = "Retrieves a list of open network ports for a specific Wazuh agent. Returns formatted port information including local/remote IP and port, protocol, state, and associated process/PID. Supports filtering by protocol and state."
    )]
    async fn get_wazuh_agent_ports(
        &self,
        Parameters(params): Parameters<GetAgentPortsParams>,
    ) -> Result<CallToolResult, McpError> {
        self.agent_tools.get_wazuh_agent_ports(params).await
    }

    #[tool(
        name = "get_wazuh_weekly_stats",
        description = "Retrieves weekly statistics from the Wazuh manager. Returns a JSON object detailing various metrics aggregated over the past week."
    )]
    async fn get_wazuh_weekly_stats(
        &self,
        Parameters(params): Parameters<GetWeeklyStatsParams>,
    ) -> Result<CallToolResult, McpError> {
        self.stats_tools.get_wazuh_weekly_stats(params).await
    }

    // ========================================================================
    // SOC Final Report Tool
    // ========================================================================

    #[tool(
        name = "generate_soc_final_report",
        description = "Generate a complete SOC final report with all analyzed incidents, response actions, long-term recommendations, and metrics CSV; then send it to admin."
    )]
    async fn generate_soc_final_report(
        &self,
        Parameters(params): Parameters<GenerateSocFinalReportParams>,
    ) -> Result<CallToolResult, McpError> {
        let period_hours = params.period_hours.unwrap_or(24);
        let metrics = self
            .metrics_tools
            .get_metrics_json(None, Some(period_hours))
            .await;
        let csv_data = self.metrics_tools.export_metrics_csv_string().await;
        let actions = self.response_tools.get_action_history_snapshot().await;
        let now = chrono::Utc::now();

        let output_dir =
            env::var("WAZUH_REPORT_OUTPUT_DIR").unwrap_or_else(|_| "/tmp".to_string());
        let csv_path = format!(
            "{}/wazuh_metrics_{}.csv",
            output_dir,
            now.format("%Y%m%d_%H%M%S")
        );
        fs::write(&csv_path, csv_data.as_bytes()).map_err(|e| {
            McpError::internal_error(
                "metrics_csv_write_failed",
                Some(json!({ "path": csv_path, "error": e.to_string() })),
            )
        })?;

        let detailed_incidents = metrics
            .get("detailed_incidents")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut per_incident = String::new();
        for incident in detailed_incidents.iter() {
            let alert_id = incident
                .get("alert_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let scenario = incident
                .get("attack_scenario")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let conclusion = incident
                .get("analysis_conclusion")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let response_action = incident
                .get("response_action")
                .and_then(|v| v.as_str())
                .unwrap_or("none");
            let response_success = incident
                .get("response_success")
                .map(|v| v.to_string())
                .unwrap_or_else(|| "null".to_string());

            let action_lines: Vec<String> = actions
                .iter()
                .filter(|a| a.alert_id == alert_id)
                .map(|a| {
                    format!(
                        "- {} | target={} | status={} | reason={}",
                        a.action_type, a.target, a.status, a.reason
                    )
                })
                .collect();

            let actions_text = if action_lines.is_empty() {
                "- no active response action recorded".to_string()
            } else {
                action_lines.join("\n")
            };

            per_incident.push_str(&format!(
                "\n### Alert {}\n- Scenario: {}\n- Analysis Conclusion: {}\n- Response Action: {}\n- Response Success: {}\n- Actions Taken:\n{}\n",
                alert_id, scenario, conclusion, response_action, response_success, actions_text
            ));
        }

        let long_term_actions = [
            "Tune noisy detection rules to reduce false positives while preserving critical coverage.",
            "Enable and validate all required active-response commands on manager/agents.",
            "Apply least-privilege API credentials and rotate credentials regularly.",
            "Create playbook mappings from high-confidence rules to deterministic response actions.",
            "Run weekly review of MTTA/MTTC/MTTR trends and failed response attempts.",
        ]
        .join("\n- ");

        let analyst_notes = params
            .analyst_notes
            .unwrap_or_else(|| "No additional analyst notes.".to_string());

        let report_body = format!(
            "# SOC Final Incident Report\n\
Generated At: {}\n\
Period (hours): {}\n\
\n## Executive Summary\n\
- Total incidents analyzed: {}\n\
- Classification metrics and response effectiveness are included in the attached CSV and inline JSON summary below.\n\
\n## Metrics Summary (JSON)\n\
```json\n{}\n```\n\
\n## Per-Incident Analysis and Actions\n{}\
\n## Long-Term Actions\n\
- {}\n\
\n## Analyst Notes\n\
{}\n",
            now.to_rfc3339(),
            period_hours,
            detailed_incidents.len(),
            serde_json::to_string_pretty(&metrics).unwrap_or_else(|_| "{}".to_string()),
            per_incident,
            long_term_actions,
            analyst_notes,
        );

        let report_path = format!(
            "{}/wazuh_soc_report_{}.md",
            output_dir,
            now.format("%Y%m%d_%H%M%S")
        );
        fs::write(&report_path, report_body.as_bytes()).map_err(|e| {
            McpError::internal_error(
                "report_write_failed",
                Some(json!({ "path": report_path, "error": e.to_string() })),
            )
        })?;

        let subject = params.subject.unwrap_or_else(|| {
            format!(
                "Wazuh SOC Final Report - {}h window ({})",
                period_hours,
                now.to_rfc3339()
            )
        });

        self.notification_tools
            .send_analysis_report(SendAnalysisReportParams {
                recipient: params.recipient.clone(),
                subject: subject.clone(),
                report_content: report_body.clone(),
                alert_id: None,
                include_metrics: Some(true),
                attachment_paths: Some(vec![report_path.clone(), csv_path.clone()]),
            })
            .await?;

        let actions_json = serde_json::to_string(&actions).unwrap_or_else(|_| "[]".to_string());
        self.notification_tools
            .send_action_summary(SendActionSummaryParams {
                recipient: params.recipient,
                alert_id: "bulk-final-report".to_string(),
                actions: actions_json,
                summary: format!(
                    "Final SOC report for {} incidents in last {} hours",
                    detailed_incidents.len(),
                    period_hours
                ),
            })
            .await?;

        let result = json!({
            "status": "completed",
            "csv_path": csv_path,
            "report_path": report_path,
            "report_subject": subject,
            "incidents_included": detailed_incidents.len(),
            "actions_included": actions.len(),
            "report_send_status": "queued_to_manager_via_send_analysis_report",
            "action_summary_send_status": "queued_to_manager_via_send_action_summary",
        });

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&result).unwrap(),
        )]))
    }

    // ========================================================================
    // Phase 2 Active Response Tools (all Wazuh built-in AR scripts)
    // ========================================================================

    #[tool(
        name = "block_ip_address",
        description = "Block an IP address using Wazuh built-in firewall-drop (iptables DROP rule). Uses PUT /active-response with command firewall-drop and alert.data.srcip. Supports IPv4 and IPv6."
    )]
    async fn block_ip_address(
        &self,
        Parameters(params): Parameters<BlockIpParams>,
    ) -> Result<CallToolResult, McpError> {
        self.response_tools.block_ip_address(params).await
    }

    #[tool(
        name = "firewalld_drop",
        description = "Block an IP address using Wazuh built-in firewalld-drop (firewalld rich-rule). Requires firewalld installed on the target agent. Uses PUT /active-response with command firewalld-drop and alert.data.srcip."
    )]
    async fn firewalld_drop(
        &self,
        Parameters(params): Parameters<FirewalldDropParams>,
    ) -> Result<CallToolResult, McpError> {
        self.response_tools.firewalld_drop(params).await
    }

    #[tool(
        name = "host_deny",
        description = "Deny an IP address by adding it to /etc/hosts.deny using the Wazuh built-in host-deny script. Uses PUT /active-response with command host-deny and alert.data.srcip."
    )]
    async fn host_deny(
        &self,
        Parameters(params): Parameters<HostDenyParams>,
    ) -> Result<CallToolResult, McpError> {
        self.response_tools.host_deny(params).await
    }

    #[tool(
        name = "route_null",
        description = "Null-route an IP address using the Wazuh built-in route-null script. Adds a route to /dev/null for the IP. Uses PUT /active-response with command route-null and alert.data.srcip."
    )]
    async fn route_null(
        &self,
        Parameters(params): Parameters<RouteNullParams>,
    ) -> Result<CallToolResult, McpError> {
        self.response_tools.route_null(params).await
    }

    #[tool(
        name = "disable_user_account",
        description = "Disable a compromised user account on a target agent using the Wazuh built-in disable-account script. Locks the OS account. Uses PUT /active-response with command disable-account and alert.data.dstuser."
    )]
    async fn disable_user_account(
        &self,
        Parameters(params): Parameters<DisableUserParams>,
    ) -> Result<CallToolResult, McpError> {
        self.response_tools.disable_user_account(params).await
    }

    #[tool(
        name = "restart_wazuh_agent",
        description = "Restart the Wazuh agent on a target endpoint using the Wazuh built-in restart-wazuh script. Useful after configuration changes. Uses PUT /active-response with command restart-wazuh."
    )]
    async fn restart_wazuh_agent(
        &self,
        Parameters(params): Parameters<RestartAgentParams>,
    ) -> Result<CallToolResult, McpError> {
        self.response_tools.restart_wazuh_agent(params).await
    }

    #[tool(
        name = "get_response_history",
        description = "Get history of all response actions taken by the MCP server. Returns action log with timestamps, targets, and results."
    )]
    async fn get_response_history(
        &self,
        Parameters(params): Parameters<GetResponseHistoryParams>,
    ) -> Result<CallToolResult, McpError> {
        self.response_tools.get_response_history(params).await
    }

    // ========================================================================
    // Phase 2 Metrics & Timing Tools
    // ========================================================================

    #[tool(
        name = "start_analysis",
        description = "Start tracking analysis time for an alert. Call this when beginning to analyze an alert. Used to measure MTTA (Mean Time To Analyze)."
    )]
    async fn start_analysis(
        &self,
        Parameters(params): Parameters<StartAnalysisParams>,
    ) -> Result<CallToolResult, McpError> {
        self.metrics_tools.start_analysis(params).await
    }

    #[tool(
        name = "end_analysis",
        description = "End tracking analysis time for an alert. Call this when analysis is complete. Records analysis duration and conclusion (TP/FP)."
    )]
    async fn end_analysis(
        &self,
        Parameters(params): Parameters<EndAnalysisParams>,
    ) -> Result<CallToolResult, McpError> {
        self.metrics_tools.end_analysis(params).await
    }

    #[tool(
        name = "start_response",
        description = "Start tracking response action time. Call this when beginning a response action (before block_ip, kill_process, etc). Used to measure MTTC (Mean Time To Contain)."
    )]
    async fn start_response(
        &self,
        Parameters(params): Parameters<StartResponseParams>,
    ) -> Result<CallToolResult, McpError> {
        self.metrics_tools.start_response(params).await
    }

    #[tool(
        name = "end_response",
        description = "End tracking response action time. Call this after response action completes. Records MTTR (Mean Time To Resolve) and response success/failure."
    )]
    async fn end_response(
        &self,
        Parameters(params): Parameters<EndResponseParams>,
    ) -> Result<CallToolResult, McpError> {
        self.metrics_tools.end_response(params).await
    }

    #[tool(
        name = "get_metrics",
        description = "Get aggregated incident response metrics. Returns MTTD, MTTA, MTTC, MTTR, dwell time, detection rate, false positive rate. Essential for Phase 1 vs Phase 2 comparison."
    )]
    async fn get_metrics(
        &self,
        Parameters(params): Parameters<GetMetricsParams>,
    ) -> Result<CallToolResult, McpError> {
        self.metrics_tools.get_metrics(params).await
    }

    #[tool(
        name = "export_metrics_csv",
        description = "Export all metrics to CSV format for research analysis. Returns CSV data that can be imported into Excel or analysis tools."
    )]
    async fn export_metrics_csv(&self) -> Result<CallToolResult, McpError> {
        self.metrics_tools.export_metrics_csv().await
    }

    // ========================================================================
    // Phase 2 Threat Intelligence Tools
    // ========================================================================

    // ========================================================================
    // Phase 2 Notification Tools
    // ========================================================================

    #[tool(
        name = "send_analysis_report",
        description = "Send a complete analysis report via email to the Wazuh administrator. Use this after completing alert analysis to notify the admin."
    )]
    async fn send_analysis_report(
        &self,
        Parameters(params): Parameters<SendAnalysisReportParams>,
    ) -> Result<CallToolResult, McpError> {
        self.notification_tools.send_analysis_report(params).await
    }

    #[tool(
        name = "send_action_summary",
        description = "Send a summary of response actions taken via email. Use this after executing response actions (block IP, kill process, etc.) to notify the admin."
    )]
    async fn send_action_summary(
        &self,
        Parameters(params): Parameters<SendActionSummaryParams>,
    ) -> Result<CallToolResult, McpError> {
        self.notification_tools.send_action_summary(params).await
    }

    // ========================================================================
    // Webhook Alert Tools - For AI to access incoming alerts
    // ========================================================================

    // Webhook tools disabled for Phase 0 - use scheduler instead
    // To re-enable webhook tools, uncomment the methods below
    /*
    #[tool(
        name = "get_recent_webhook_alerts",
        description = "Retrieves recent alerts received via webhook."
    )]
    async fn get_recent_webhook_alerts(
        &self,
        Parameters(params): Parameters<GetRecentWebhookAlertsParams>,
    ) -> Result<CallToolResult, McpError> {
        self.webhook_tools.get_recent_webhook_alerts(params).await
    }

    #[tool(
        name = "mark_webhook_alert_processed",
        description = "Marks a webhook alert as processed."
    )]
    async fn mark_webhook_alert_processed(
        &self,
        Parameters(params): Parameters<MarkAlertProcessedParams>,
    ) -> Result<CallToolResult, McpError> {
        self.webhook_tools.mark_webhook_alert_processed(params).await
    }
    */
}

#[tool_handler]
impl ServerHandler for WazuhToolsServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2025_06_18,
            server_info: Implementation {
                name: env!("CARGO_PKG_NAME").to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                ..Default::default()
            },
            instructions: Some(
                "You are a senior SOC engineer operating this Wazuh MCP server in manual analyst mode (no autonomous scheduler/orchestrator).\n\nYour primary task is to analyze and respond to existing Wazuh alerts within a user-provided time window. Use `get_wazuh_alerts_in_time_range` when the user provides start/end timestamps; use `get_wazuh_alert_summary` only when no window is provided.\n\nUse this workflow for each incident:\n1) Gather context with `get_wazuh_alerts_in_time_range` (preferred for time windows), `get_wazuh_rules_summary`, `get_wazuh_agents`, and `get_wazuh_agent_ports` when needed.\n2) Start timing with `start_analysis`.\n3) Conclude analysis with `end_analysis` using `true_positive`, `false_positive`, or `unknown`.\n4) For confirmed threats, execute active response and track timing with `start_response` and `end_response`. Available active responses (all Wazuh built-in):\n   - `block_ip_address` (firewall-drop via iptables)\n   - `firewalld_drop` (firewalld rich-rule, requires firewalld)\n   - `host_deny` (adds IP to /etc/hosts.deny)\n   - `route_null` (null-routes the IP)\n   - `disable_user_account` (locks OS user account)\n   - `restart_wazuh_agent` (restarts agent after config change)\n5) After handling incidents, call `generate_soc_final_report` to create a comprehensive report, generate metrics CSV, and send the final report + metrics attachments and an action summary to the admin.\n\nResponse examples:\n- Brute force or repeated auth failures: block source IP with `block_ip_address`.\n- Persistent attacker on firewalld host: use `firewalld_drop`.\n- Hosts.deny-based blocking: use `host_deny`.\n- Network-level isolation: use `route_null` to null-route attacker IP.\n- Confirmed compromised account: disable with `disable_user_account`.\n- Agent config change applied: restart agent with `restart_wazuh_agent`.\n\nAlways preserve auditability, minimize false positives, and prefer least-destructive effective actions."
                    .to_string(),
            ),
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .build(),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::DEBUG.into()),
        )
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("Starting Wazuh MCP Server...");

    match args.transport.as_str() {
        "stdio" => {
            tracing::info!("Using stdio transport");
            let server = WazuhToolsServer::new().expect("Error initializing Wazuh tools server");
            let service = server.serve(stdio()).await.inspect_err(|e| {
                tracing::error!("serving error: {:?}", e);
            })?;
            service.waiting().await?;
        }
        #[cfg(feature = "http")]
        "http" => {
            use axum::Router;

            tracing::info!("Starting HTTP server on {}:{}", args.host, args.port);
            let addr = format!("{}:{}", args.host, args.port);

            // Initialize a single shared server instance.
            let shared_server =
                Arc::new(WazuhToolsServer::new().expect("Error initializing Wazuh tools server"));

            let service = StreamableHttpService::new(
                // Provide a factory that clones the shared server for each session
                move || Ok((*(shared_server.clone())).clone()),
                Arc::new(LocalSessionManager::default()),
                StreamableHttpServerConfig::default(),
            );

            let router = Router::new().nest_service("/mcp", service);

            let tcp_listener = tokio::net::TcpListener::bind(&addr).await?;

            tracing::info!("Listening on http://{}/mcp", addr);

            axum::serve(tcp_listener, router)
                .with_graceful_shutdown(async {
                    tokio::signal::ctrl_c().await.unwrap();
                    tracing::info!("Received Ctrl-C, shutting down...");
                })
                .await?;
        }
        #[cfg(not(feature = "http"))]
        "http" => {
            anyhow::bail!(
                "HTTP transport is not enabled. Rebuild with the 'http' feature: cargo build --features http"
            );
        }
        _ => {
            anyhow::bail!(
                "Unknown transport: '{}'. Use 'stdio' or 'http'",
                args.transport
            );
        }
    }

    Ok(())
}
