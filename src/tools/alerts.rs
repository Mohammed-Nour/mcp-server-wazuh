//! Wazuh Indexer alert tools
//!
//! This module contains tools for retrieving and analyzing Wazuh security alerts
//! from the Wazuh Indexer.

use super::ToolModule;
use chrono::{DateTime, Utc};
use rmcp::{
    model::{CallToolResult, Content},
    tool, ErrorData as McpError,
};
use std::sync::Arc;
use std::time::Duration;
use wazuh_client::WazuhIndexerClient;

/// Parameters for getting alert summary
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct GetAlertSummaryParams {
    #[schemars(description = "Maximum number of alerts to retrieve (default: 300)")]
    pub limit: Option<u32>,
}

/// Parameters for getting alerts within a time range (UTC timestamps)
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct GetAlertsInTimeRangeParams {
    #[schemars(
        description = "Start timestamp (inclusive). Accepts RFC3339 like '2026-02-15T10:00:00Z' or offsets like '+0000'."
    )]
    pub start_timestamp: String,

    #[schemars(
        description = "End timestamp (inclusive). Accepts RFC3339 like '2026-02-15T11:00:00Z' or offsets like '+0000'."
    )]
    pub end_timestamp: String,

    #[schemars(
        description = "Maximum number of raw alerts to fetch before filtering (default: 1000)."
    )]
    pub fetch_limit: Option<u32>,

    #[schemars(description = "Maximum number of alerts to return after filtering (default: 300).")]
    pub return_limit: Option<u32>,

    #[schemars(
        description = "Whether to include the full raw alert JSON payload for each result (default: false)."
    )]
    pub include_raw: Option<bool>,
}

/// Alert tools implementation
#[derive(Clone)]
pub struct AlertTools {
    indexer_client: Arc<WazuhIndexerClient>,
}

impl AlertTools {
    pub fn new(indexer_client: Arc<WazuhIndexerClient>) -> Self {
        Self { indexer_client }
    }

    /// Internal helper for scheduler/autonomous paths that need raw JSON alerts.
    pub async fn fetch_recent_alerts(
        &self,
        limit: Option<u32>,
    ) -> Result<Vec<serde_json::Value>, String> {
        let limit = limit.unwrap_or(300);
        self.indexer_client
            .get_alerts(Some(limit))
            .await
            .map_err(|e| format!("Failed to fetch alerts: {}", e))
    }

    #[tool(
        name = "get_wazuh_alert_summary",
        description = "Retrieves a summary of Wazuh security alerts. Returns formatted alert information including ID, timestamp, and description."
    )]
    pub async fn get_wazuh_alert_summary(
        &self,
        params: GetAlertSummaryParams,
    ) -> Result<CallToolResult, McpError> {
        let limit = params.limit.unwrap_or(300);

        tracing::info!(limit = %limit, "Retrieving Wazuh alert summary");

        match self.indexer_client.get_alerts(Some(limit)).await {
            Ok(raw_alerts) => {
                if raw_alerts.is_empty() {
                    tracing::info!("No Wazuh alerts found to process. Returning standard message.");
                    return Self::not_found_result("Wazuh alerts");
                }

                let num_alerts_to_process = raw_alerts.len();
                let mcp_content_items: Vec<Content> = raw_alerts
                    .into_iter()
                    .map(|alert_value| {
                        let source = alert_value.get("_source").unwrap_or(&alert_value);

                        let id = source
                            .get("id")
                            .and_then(|v| v.as_str())
                            .or_else(|| alert_value.get("_id").and_then(|v| v.as_str()))
                            .unwrap_or("Unknown ID");

                        let description = source
                            .get("rule")
                            .and_then(|r| r.get("description"))
                            .and_then(|d| d.as_str())
                            .unwrap_or("No description available");

                        let timestamp = source
                            .get("timestamp")
                            .and_then(|t| t.as_str())
                            .unwrap_or("Unknown time");

                        let agent_name = source
                            .get("agent")
                            .and_then(|a| a.get("name"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("Unknown agent");

                        let rule_level = source
                            .get("rule")
                            .and_then(|r| r.get("level"))
                            .and_then(|l| l.as_u64())
                            .unwrap_or(0);

                        // Extract source IP from data.srcip (common for SSH, network alerts)
                        let src_ip = source
                            .get("data")
                            .and_then(|d| d.get("srcip"))
                            .and_then(|ip| ip.as_str())
                            .or_else(|| {
                                source
                                    .get("data")
                                    .and_then(|d| d.get("src_ip"))
                                    .and_then(|ip| ip.as_str())
                            })
                            .unwrap_or("");

                        // Extract destination IP if available
                        let dst_ip = source
                            .get("data")
                            .and_then(|d| d.get("dstip"))
                            .and_then(|ip| ip.as_str())
                            .or_else(|| {
                                source
                                    .get("data")
                                    .and_then(|d| d.get("dst_ip"))
                                    .and_then(|ip| ip.as_str())
                            })
                            .unwrap_or("");

                        // Extract source user if available
                        let src_user = source
                            .get("data")
                            .and_then(|d| d.get("srcuser"))
                            .and_then(|u| u.as_str())
                            .or_else(|| {
                                source
                                    .get("data")
                                    .and_then(|d| d.get("dstuser"))
                                    .and_then(|u| u.as_str())
                            })
                            .unwrap_or("");

                        // Build formatted text with optional fields
                        let mut formatted_text = format!(
                            "Alert ID: {}\nTime: {}\nAgent: {}\nLevel: {}\nDescription: {}",
                            id, timestamp, agent_name, rule_level, description
                        );

                        if !src_ip.is_empty() {
                            formatted_text.push_str(&format!("\nSource IP: {}", src_ip));
                        }
                        if !dst_ip.is_empty() {
                            formatted_text.push_str(&format!("\nDestination IP: {}", dst_ip));
                        }
                        if !src_user.is_empty() {
                            formatted_text.push_str(&format!("\nUser: {}", src_user));
                        }
                        Content::text(formatted_text)
                    })
                    .collect();

                tracing::info!(
                    "Successfully processed {} alerts into {} MCP content items",
                    num_alerts_to_process,
                    mcp_content_items.len()
                );
                Self::success_result(mcp_content_items)
            }
            Err(e) => {
                let err_msg = Self::format_error("Indexer", "retrieving alerts", &e);
                tracing::error!("{}", err_msg);
                Self::error_result(err_msg)
            }
        }
    }

    #[tool(
        name = "get_wazuh_alerts_in_time_range",
        description = "Retrieves Wazuh alerts within a specific timestamp range (inclusive). This is useful for analyzing existing alerts between two timestamps without any scheduler. Returns a JSON array of alert objects."
    )]
    pub async fn get_wazuh_alerts_in_time_range(
        &self,
        params: GetAlertsInTimeRangeParams,
    ) -> Result<CallToolResult, McpError> {
        let start = Self::parse_timestamp_any(&params.start_timestamp)
            .ok_or_else(|| McpError::invalid_request("invalid_start_timestamp", None))?;
        let end = Self::parse_timestamp_any(&params.end_timestamp)
            .ok_or_else(|| McpError::invalid_request("invalid_end_timestamp", None))?;

        if end < start {
            return Self::error_result("end_timestamp must be >= start_timestamp".to_string());
        }

        let fetch_limit = params.fetch_limit.unwrap_or(1000);
        let return_limit = params.return_limit.unwrap_or(300) as usize;
        let include_raw = params.include_raw.unwrap_or(false);

        // IMPORTANT: Do a real time-range query against the Indexer.
        // Filtering "latest N" alerts client-side is not reliable when the Indexer has high volume.
        let raw_alerts = self
            .query_indexer_alerts_in_range(start, end, fetch_limit)
            .await
            .map_err(|e| {
                McpError::internal_error(
                    "indexer_time_range_query_failed",
                    Some(serde_json::json!({"error": e})),
                )
            })?;

        let items: Vec<serde_json::Value> = raw_alerts
            .into_iter()
            .take(return_limit)
            .map(|(ts, alert_value)| {
                let source = alert_value.get("_source").unwrap_or(&alert_value);

                let id = source
                    .get("id")
                    .and_then(|v| v.as_str())
                    .or_else(|| alert_value.get("_id").and_then(|v| v.as_str()))
                    .unwrap_or("unknown");

                let description = source
                    .get("rule")
                    .and_then(|r| r.get("description"))
                    .and_then(|d| d.as_str())
                    .unwrap_or("");

                let agent_name = source
                    .get("agent")
                    .and_then(|a| a.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("");

                let agent_id = source
                    .get("agent")
                    .and_then(|a| a.get("id"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("");

                let rule_id = source
                    .get("rule")
                    .and_then(|r| r.get("id"))
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);

                let rule_level = source
                    .get("rule")
                    .and_then(|r| r.get("level"))
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);

                let src_ip = source
                    .get("data")
                    .and_then(|d| d.get("srcip"))
                    .and_then(|ip| ip.as_str())
                    .or_else(|| {
                        source
                            .get("data")
                            .and_then(|d| d.get("src_ip"))
                            .and_then(|ip| ip.as_str())
                    })
                    .unwrap_or("");

                let dst_user = source
                    .get("data")
                    .and_then(|d| d.get("dstuser"))
                    .and_then(|u| u.as_str())
                    .unwrap_or("");

                let src_user = source
                    .get("data")
                    .and_then(|d| d.get("srcuser"))
                    .and_then(|u| u.as_str())
                    .unwrap_or("");

                let mut obj = serde_json::Map::new();
                obj.insert("alert_id".to_string(), serde_json::Value::String(id.to_string()));
                obj.insert(
                    "timestamp".to_string(),
                    serde_json::Value::String(ts.to_rfc3339()),
                );
                obj.insert(
                    "agent".to_string(),
                    serde_json::json!({"id": agent_id, "name": agent_name}),
                );
                obj.insert(
                    "rule".to_string(),
                    serde_json::json!({"id": rule_id, "level": rule_level, "description": description}),
                );
                obj.insert(
                    "data".to_string(),
                    serde_json::json!({"srcip": src_ip, "srcuser": src_user, "dstuser": dst_user}),
                );

                if include_raw {
                    obj.insert("raw".to_string(), alert_value);
                }

                serde_json::Value::Object(obj)
            })
            .collect();

        let response = serde_json::json!({
            "status": "ok",
            "start_timestamp": start.to_rfc3339(),
            "end_timestamp": end.to_rfc3339(),
            "returned": items.len(),
            "alerts": items,
        });

        Self::success_result(vec![Content::text(
            serde_json::to_string_pretty(&response).unwrap_or_else(|_| "{}".to_string()),
        )])
    }

    fn parse_timestamp_any(input: &str) -> Option<DateTime<Utc>> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return None;
        }

        // RFC3339: 2026-02-15T10:00:00Z or +00:00
        if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
            return Some(dt.with_timezone(&Utc));
        }

        // Wazuh/legacy style: +0000 (no colon)
        for fmt in [
            "%Y-%m-%dT%H:%M:%S%.f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S%.f%z",
            "%Y-%m-%d %H:%M:%S%z",
        ] {
            if let Ok(dt) = chrono::DateTime::parse_from_str(trimmed, fmt) {
                return Some(dt.with_timezone(&Utc));
            }
        }

        None
    }

    async fn query_indexer_alerts_in_range(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        size: u32,
    ) -> Result<Vec<(DateTime<Utc>, serde_json::Value)>, String> {
        // Use env vars directly so we can execute a true range query.
        // (The wazuh-client indexer wrapper currently exposes only "latest N".)
        let protocol = std::env::var("WAZUH_TEST_PROTOCOL").unwrap_or_else(|_| "https".to_string());
        let mut host =
            std::env::var("WAZUH_INDEXER_HOST").unwrap_or_else(|_| "localhost".to_string());
        if host.starts_with("http://") {
            host = host.trim_start_matches("http://").to_string();
        }
        if host.starts_with("https://") {
            host = host.trim_start_matches("https://").to_string();
        }

        let port = std::env::var("WAZUH_INDEXER_PORT").unwrap_or_else(|_| "9200".to_string());
        let username =
            std::env::var("WAZUH_INDEXER_USERNAME").unwrap_or_else(|_| "admin".to_string());
        let password = std::env::var("WAZUH_INDEXER_PASSWORD").unwrap_or_default();
        if password.is_empty() {
            return Err(
                "WAZUH_INDEXER_PASSWORD is empty; required for Indexer range query".to_string(),
            );
        }
        let verify_ssl = std::env::var("WAZUH_VERIFY_SSL")
            .ok()
            .and_then(|v| v.parse::<bool>().ok())
            .unwrap_or(false);

        let base_url = format!("{}://{}:{}", protocol, host, port);
        let endpoint = format!("{}/wazuh-alerts*/_search", base_url.trim_end_matches('/'));

        let query = serde_json::json!({
            "query": {
                "range": {
                    "timestamp": {
                        "gte": start.to_rfc3339(),
                        "lte": end.to_rfc3339(),
                    }
                }
            },
            "size": size,
            "sort": [
                {"timestamp": {"order": "asc"}}
            ]
        });

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(!verify_ssl)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .user_agent("mcp-server-wazuh/alerts")
            .build()
            .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

        let resp = client
            .post(&endpoint)
            .basic_auth(username, Some(password))
            .json(&query)
            .send()
            .await
            .map_err(|e| format!("Indexer request failed: {}", e))?;

        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| format!("Failed to read Indexer response body: {}", e))?;
        if !status.is_success() {
            return Err(format!("Indexer returned {}: {}", status.as_u16(), body));
        }

        let parsed: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| format!("Failed to parse Indexer JSON: {}", e))?;

        let hits = parsed
            .get("hits")
            .and_then(|h| h.get("hits"))
            .and_then(|h| h.as_array())
            .cloned()
            .unwrap_or_default();

        let mut out: Vec<(DateTime<Utc>, serde_json::Value)> = Vec::new();
        for hit in hits.into_iter() {
            let source = hit.get("_source").unwrap_or(&hit);
            let ts_str = source
                .get("timestamp")
                .and_then(|t| t.as_str())
                .unwrap_or("");
            let Some(ts) = Self::parse_timestamp_any(ts_str) else {
                continue;
            };
            out.push((ts, hit));
        }

        Ok(out)
    }
}

impl ToolModule for AlertTools {}
