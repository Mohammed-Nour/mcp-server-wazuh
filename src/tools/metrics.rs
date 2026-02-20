//! Metrics and Timing Module
//!
//! Automatically tracks incident response metrics for research:
//! - MTTD (Mean Time To Detect) - Alert generation time
//! - MTTA (Mean Time To Acknowledge/Analyze) - Analysis start to end
//! - MTTC (Mean Time To Contain) - Response action start
//! - MTTR (Mean Time To Resolve) - Full incident resolution
//! - Dwell Time - Attack start to full resolution

use chrono::{DateTime, Utc};
use rmcp::{
    model::{CallToolResult, Content},
    schemars, ErrorData as McpError,
};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::tools::ToolModule;

// ============================================================================
// Parameter Structures
// ============================================================================

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct StartAnalysisParams {
    /// Alert ID being analyzed
    #[schemars(description = "Wazuh alert ID")]
    pub alert_id: String,

    /// Attack scenario name (for grouping)
    #[schemars(description = "Attack scenario name (e.g., 'SSH Brute Force')")]
    pub attack_scenario: String,

    /// Alert timestamp (when Wazuh detected it)
    #[schemars(description = "Alert detection timestamp (ISO 8601)")]
    pub alert_timestamp: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct EndAnalysisParams {
    /// Alert ID
    #[schemars(description = "Wazuh alert ID")]
    pub alert_id: String,

    /// Analysis conclusion (TP, FP, etc.)
    #[schemars(description = "Analysis conclusion: 'true_positive', 'false_positive', 'unknown'")]
    pub conclusion: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct StartResponseParams {
    /// Alert ID
    #[schemars(description = "Wazuh alert ID")]
    pub alert_id: String,

    /// Response action type
    #[schemars(description = "Response action (e.g., 'block_ip', 'kill_process')")]
    pub action_type: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct EndResponseParams {
    /// Alert ID
    #[schemars(description = "Wazuh alert ID")]
    pub alert_id: String,

    /// Whether response was successful
    #[schemars(description = "Response success status")]
    pub success: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct GetMetricsParams {
    /// Attack scenario filter (optional)
    #[schemars(description = "Filter by attack scenario (optional)")]
    pub attack_scenario: Option<String>,

    /// Time period in hours (optional)
    #[schemars(description = "Time period in hours (default: 24)")]
    pub period_hours: Option<u32>,
}

// ============================================================================
// Metric Tracking Structures
// ============================================================================

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IncidentMetrics {
    pub alert_id: String,
    pub attack_scenario: String,

    // Detection
    pub alert_detected_at: DateTime<Utc>,

    // Analysis
    pub analysis_started_at: Option<DateTime<Utc>>,
    pub analysis_ended_at: Option<DateTime<Utc>>,
    pub analysis_duration_ms: Option<i64>,
    pub analysis_conclusion: Option<String>,

    // Response
    pub response_started_at: Option<DateTime<Utc>>,
    pub response_ended_at: Option<DateTime<Utc>>,
    pub response_duration_ms: Option<i64>,
    pub response_action: Option<String>,
    pub response_success: Option<bool>,

    // Calculated metrics
    pub mtta_ms: Option<i64>,       // Detection to analysis start
    pub mttc_ms: Option<i64>,       // Detection to containment (response) start
    pub mttr_ms: Option<i64>,       // Detection to resolution (response end)
    pub dwell_time_ms: Option<i64>, // Total time (detection to resolution)
}

// ============================================================================
// Metrics Tools Implementation
// ============================================================================

#[derive(Clone)]
pub struct MetricsTools {
    incidents: Arc<Mutex<Vec<IncidentMetrics>>>,
}

impl MetricsTools {
    pub fn new() -> Self {
        Self {
            incidents: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Start tracking analysis for an alert
    pub async fn start_analysis(
        &self,
        params: StartAnalysisParams,
    ) -> Result<CallToolResult, McpError> {
        let now = Utc::now();

        // Parse alert timestamp
        let alert_time = DateTime::parse_from_rfc3339(&params.alert_timestamp)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| now);

        let mut incidents = self.incidents.lock().await;

        // Check if incident already exists
        if let Some(incident) = incidents.iter_mut().find(|i| i.alert_id == params.alert_id) {
            incident.analysis_started_at = Some(now);
            incident.mtta_ms = Some((now - incident.alert_detected_at).num_milliseconds());
        } else {
            // Create new incident
            let incident = IncidentMetrics {
                alert_id: params.alert_id.clone(),
                attack_scenario: params.attack_scenario.clone(),
                alert_detected_at: alert_time,
                analysis_started_at: Some(now),
                analysis_ended_at: None,
                analysis_duration_ms: None,
                analysis_conclusion: None,
                response_started_at: None,
                response_ended_at: None,
                response_duration_ms: None,
                response_action: None,
                response_success: None,
                mtta_ms: Some((now - alert_time).num_milliseconds()),
                mttc_ms: None,
                mttr_ms: None,
                dwell_time_ms: None,
            };
            incidents.push(incident);
        }

        let response = json!({
            "status": "analysis_started",
            "alert_id": params.alert_id,
            "started_at": now.to_rfc3339(),
        });

        Self::success_result(vec![Content::text(
            serde_json::to_string_pretty(&response).unwrap(),
        )])
    }

    /// End analysis tracking
    pub async fn end_analysis(
        &self,
        params: EndAnalysisParams,
    ) -> Result<CallToolResult, McpError> {
        let now = Utc::now();
        let mut incidents = self.incidents.lock().await;

        if let Some(incident) = incidents.iter_mut().find(|i| i.alert_id == params.alert_id) {
            incident.analysis_ended_at = Some(now);
            incident.analysis_conclusion = Some(params.conclusion.clone());

            if let Some(start) = incident.analysis_started_at {
                incident.analysis_duration_ms = Some((now - start).num_milliseconds());
            }

            let response = json!({
                "status": "analysis_completed",
                "alert_id": params.alert_id,
                "ended_at": now.to_rfc3339(),
                "duration_ms": incident.analysis_duration_ms,
                "conclusion": params.conclusion,
            });

            Self::success_result(vec![Content::text(
                serde_json::to_string_pretty(&response).unwrap(),
            )])
        } else {
            Self::error_result(format!(
                "No analysis found for alert ID: {}",
                params.alert_id
            ))
        }
    }

    /// Start response action tracking
    pub async fn start_response(
        &self,
        params: StartResponseParams,
    ) -> Result<CallToolResult, McpError> {
        let now = Utc::now();
        let mut incidents = self.incidents.lock().await;

        if let Some(incident) = incidents.iter_mut().find(|i| i.alert_id == params.alert_id) {
            incident.response_started_at = Some(now);
            incident.response_action = Some(params.action_type.clone());
            incident.mttc_ms = Some((now - incident.alert_detected_at).num_milliseconds());

            let response = json!({
                "status": "response_started",
                "alert_id": params.alert_id,
                "action": params.action_type,
                "started_at": now.to_rfc3339(),
            });

            Self::success_result(vec![Content::text(
                serde_json::to_string_pretty(&response).unwrap(),
            )])
        } else {
            Self::error_result(format!(
                "No incident found for alert ID: {}",
                params.alert_id
            ))
        }
    }

    /// End response action tracking
    pub async fn end_response(
        &self,
        params: EndResponseParams,
    ) -> Result<CallToolResult, McpError> {
        let now = Utc::now();
        let mut incidents = self.incidents.lock().await;

        if let Some(incident) = incidents.iter_mut().find(|i| i.alert_id == params.alert_id) {
            incident.response_ended_at = Some(now);
            incident.response_success = Some(params.success);

            if let Some(start) = incident.response_started_at {
                incident.response_duration_ms = Some((now - start).num_milliseconds());
            }

            // Calculate MTTR and dwell time
            incident.mttr_ms = Some((now - incident.alert_detected_at).num_milliseconds());
            incident.dwell_time_ms = incident.mttr_ms;

            let response = json!({
                "status": "response_completed",
                "alert_id": params.alert_id,
                "ended_at": now.to_rfc3339(),
                "duration_ms": incident.response_duration_ms,
                "success": params.success,
                "mttr_ms": incident.mttr_ms,
            });

            Self::success_result(vec![Content::text(
                serde_json::to_string_pretty(&response).unwrap(),
            )])
        } else {
            Self::error_result(format!(
                "No incident found for alert ID: {}",
                params.alert_id
            ))
        }
    }

    /// Get aggregated metrics
    pub async fn get_metrics(&self, params: GetMetricsParams) -> Result<CallToolResult, McpError> {
        let report = self
            .get_metrics_json(params.attack_scenario, params.period_hours)
            .await;

        let has_data = report
            .get("total_incidents")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            > 0;

        if !has_data {
            return Self::not_found_result("metrics");
        }

        Self::success_result(vec![Content::text(
            serde_json::to_string_pretty(&report).unwrap(),
        )])
    }

    /// Export metrics to CSV format for research
    pub async fn export_metrics_csv(&self) -> Result<CallToolResult, McpError> {
        let csv = self.export_metrics_csv_string().await;
        Self::success_result(vec![Content::text(csv)])
    }

    pub async fn get_metrics_json(
        &self,
        attack_scenario: Option<String>,
        period_hours: Option<u32>,
    ) -> serde_json::Value {
        let incidents = self.incidents.lock().await;
        let period = period_hours.unwrap_or(24);
        let cutoff = Utc::now() - chrono::Duration::hours(period as i64);

        let filtered: Vec<_> = incidents
            .iter()
            .filter(|i| {
                let in_period = i.alert_detected_at > cutoff;
                let matches_scenario = attack_scenario
                    .as_ref()
                    .map(|s| &i.attack_scenario == s)
                    .unwrap_or(true);
                in_period && matches_scenario
            })
            .collect();

        if filtered.is_empty() {
            return json!({
                "period_hours": period,
                "total_incidents": 0,
                "metrics": {},
                "classifications": {},
                "response_effectiveness": {},
                "detailed_incidents": [],
            });
        }

        let total = filtered.len() as f64;

        let average = |values: Vec<i64>| -> f64 {
            if values.is_empty() {
                0.0
            } else {
                values.iter().sum::<i64>() as f64 / values.len() as f64
            }
        };

        let avg_mtta = average(filtered.iter().filter_map(|i| i.mtta_ms).collect());
        let avg_analysis_duration = average(
            filtered
                .iter()
                .filter_map(|i| i.analysis_duration_ms)
                .collect(),
        );
        let avg_mttc = average(filtered.iter().filter_map(|i| i.mttc_ms).collect());
        let avg_mttr = average(filtered.iter().filter_map(|i| i.mttr_ms).collect());
        let avg_dwell_time = average(filtered.iter().filter_map(|i| i.dwell_time_ms).collect());

        let true_positives = filtered
            .iter()
            .filter(|i| i.analysis_conclusion.as_deref() == Some("true_positive"))
            .count();
        let false_positives = filtered
            .iter()
            .filter(|i| i.analysis_conclusion.as_deref() == Some("false_positive"))
            .count();

        let response_success_count = filtered
            .iter()
            .filter(|i| i.response_success == Some(true))
            .count();
        let response_total = filtered
            .iter()
            .filter(|i| i.response_success.is_some())
            .count();

        json!({
            "period_hours": period,
            "total_incidents": total,
            "metrics": {
                "average_mttd_seconds": serde_json::Value::Null,
                "mttd_note": "MTTD requires attack start timestamps, which are not tracked by this module.",
                "average_mtta_seconds": (avg_mtta / 1000.0),
                "average_mttc_seconds": (avg_mttc / 1000.0),
                "average_mttr_seconds": (avg_mttr / 1000.0),
                "average_dwell_time_seconds": (avg_dwell_time / 1000.0),
                "average_analysis_duration_seconds": (avg_analysis_duration / 1000.0),
            },
            "classifications": {
                "true_positives": true_positives,
                "false_positives": false_positives,
                "detection_rate_percent": (true_positives as f64 / total * 100.0),
                "false_positive_rate_percent": (false_positives as f64 / total * 100.0),
            },
            "response_effectiveness": {
                "total_responses": response_total,
                "successful_responses": response_success_count,
                "success_rate_percent": if response_total > 0 {
                    response_success_count as f64 / response_total as f64 * 100.0
                } else {
                    0.0
                },
            },
            "detailed_incidents": filtered,
        })
    }

    pub async fn export_metrics_csv_string(&self) -> String {
        let incidents = self.incidents.lock().await;

        let mut csv = String::from("alert_id,attack_scenario,alert_detected_at,mtta_ms,analysis_duration_ms,mttc_ms,response_duration_ms,mttr_ms,dwell_time_ms,analysis_conclusion,response_action,response_success\n");

        for incident in incidents.iter() {
            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{},{},{}\n",
                incident.alert_id,
                incident.attack_scenario,
                incident.alert_detected_at.to_rfc3339(),
                incident.mtta_ms.map(|v| v.to_string()).unwrap_or_default(),
                incident
                    .analysis_duration_ms
                    .map(|v| v.to_string())
                    .unwrap_or_default(),
                incident.mttc_ms.map(|v| v.to_string()).unwrap_or_default(),
                incident
                    .response_duration_ms
                    .map(|v| v.to_string())
                    .unwrap_or_default(),
                incident.mttr_ms.map(|v| v.to_string()).unwrap_or_default(),
                incident
                    .dwell_time_ms
                    .map(|v| v.to_string())
                    .unwrap_or_default(),
                incident.analysis_conclusion.as_deref().unwrap_or(""),
                incident.response_action.as_deref().unwrap_or(""),
                incident
                    .response_success
                    .map(|v| if v { "true" } else { "false" })
                    .unwrap_or(""),
            ));
        }

        csv
    }

}

impl ToolModule for MetricsTools {}
