//! Email Notification Module
//!
//! Sends formatted HTML emails via SMTP with file attachments, and also logs
//! concise notification events to the Wazuh Manager /events API for auditability.

use rmcp::{
    model::{CallToolResult, Content},
    schemars, ErrorData as McpError,
};
use serde_json::json;
use std::env;
use std::time::Duration;

use crate::tools::ToolModule;

// ============================================================================
// Parameter Structures
// ============================================================================

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct SendAnalysisReportParams {
    /// Recipient email address
    #[schemars(description = "Recipient email (default: from WAZUH_ADMIN_EMAIL env)")]
    pub recipient: Option<String>,

    /// Report subject
    #[schemars(description = "Email subject")]
    pub subject: String,

    /// Report body (markdown or plain text)
    #[schemars(description = "Report content (markdown or plain text)")]
    pub report_content: String,

    /// Alert ID this report is about
    #[schemars(description = "Associated alert ID (optional)")]
    pub alert_id: Option<String>,

    /// Attach metrics JSON
    #[schemars(description = "Include metrics JSON as attachment (default: false)")]
    pub include_metrics: Option<bool>,

    /// Optional local files to include as email attachments
    #[schemars(description = "Optional list of local file paths to include with the report")]
    pub attachment_paths: Option<Vec<String>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct SendActionSummaryParams {
    /// Recipient email
    #[schemars(description = "Recipient email (default: from WAZUH_ADMIN_EMAIL env)")]
    pub recipient: Option<String>,

    /// Alert ID
    #[schemars(description = "Alert ID")]
    pub alert_id: String,

    /// Actions taken
    #[schemars(description = "JSON array of actions taken")]
    pub actions: String,

    /// Analysis summary
    #[schemars(description = "Brief analysis summary")]
    pub summary: String,
}

// ============================================================================
// Notification Tools Implementation
// ============================================================================

#[derive(Clone)]
pub struct NotificationTools {
    // Wazuh API config (for audit event logging)
    wazuh_api_base_url: String,
    wazuh_api_username: String,
    wazuh_api_password: String,
    verify_ssl: bool,
    notification_tag: String,
    admin_email: String,
    // SMTP config
    smtp_host: String,
    smtp_port: u16,
    smtp_username: String,
    smtp_password: String,
    smtp_from: String,
    smtp_enabled: bool,
}

impl NotificationTools {
    pub fn new() -> Self {
        let protocol = env::var("WAZUH_TEST_PROTOCOL").unwrap_or_else(|_| "https".to_string());
        let host = env::var("WAZUH_API_HOST").unwrap_or_else(|_| "localhost".to_string());
        let port = env::var("WAZUH_API_PORT").unwrap_or_else(|_| "55000".to_string());

        let smtp_host = env::var("SMTP_HOST").unwrap_or_default();
        let smtp_username = env::var("SMTP_USERNAME").unwrap_or_default();
        let smtp_password = env::var("SMTP_PASSWORD").unwrap_or_default();
        let smtp_enabled = !smtp_host.is_empty() && !smtp_password.is_empty();

        Self {
            wazuh_api_base_url: format!("{}://{}:{}", protocol, host, port),
            wazuh_api_username: env::var("WAZUH_API_USERNAME")
                .unwrap_or_else(|_| "wazuh".to_string()),
            wazuh_api_password: env::var("WAZUH_API_PASSWORD").unwrap_or_default(),
            verify_ssl: env::var("WAZUH_VERIFY_SSL")
                .ok()
                .and_then(|v| v.parse::<bool>().ok())
                .unwrap_or(false),
            notification_tag: env::var("WAZUH_NOTIFICATION_TAG")
                .unwrap_or_else(|_| "mcp-server-wazuh-notify".to_string()),
            admin_email: env::var("WAZUH_ADMIN_EMAIL")
                .unwrap_or_else(|_| "admin@localhost".to_string()),
            smtp_host,
            smtp_port: env::var("SMTP_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(587),
            smtp_username,
            smtp_password,
            smtp_from: env::var("SMTP_FROM")
                .unwrap_or_else(|_| env::var("SMTP_USERNAME").unwrap_or_default()),
            smtp_enabled,
        }
    }

    /// Send a formatted HTML analysis report via SMTP + Wazuh audit event
    pub async fn send_analysis_report(
        &self,
        params: SendAnalysisReportParams,
    ) -> Result<CallToolResult, McpError> {
        let recipient = params.recipient.as_ref().unwrap_or(&self.admin_email);
        let now = chrono::Utc::now();

        // Try SMTP email first
        let smtp_result = if self.smtp_enabled {
            self.send_smtp_email(
                recipient,
                &params.subject,
                &params.report_content,
                params.attachment_paths.as_deref(),
            )
            .await
        } else {
            Err("SMTP not configured (SMTP_HOST/SMTP_PASSWORD missing)".to_string())
        };

        // Also send Wazuh audit event (lightweight metadata only)
        let event_payload = json!({
            "integration": self.notification_tag,
            "mcp_report": {
                "type": "analysis_report",
                "recipient": recipient,
                "subject": params.subject,
                "alert_id": params.alert_id,
                "include_metrics": params.include_metrics.unwrap_or(false),
                "generated_at": now.to_rfc3339(),
                "smtp_sent": smtp_result.is_ok(),
                "file_paths": params.attachment_paths,
            }
        });
        let wazuh_result = self.send_manager_event(event_payload).await;

        let response = json!({
            "status": if smtp_result.is_ok() { "email_sent" } else { "email_failed" },
            "smtp_delivery": match &smtp_result {
                Ok(msg) => json!({"success": true, "message": msg}),
                Err(e) => json!({"success": false, "error": e}),
            },
            "wazuh_audit_event": match &wazuh_result {
                Ok(v) => json!({"success": true, "delivery": v}),
                Err(e) => json!({"success": false, "error": e}),
            },
            "recipient": recipient,
            "subject": params.subject,
            "timestamp": now.to_rfc3339(),
        });

        Self::success_result(vec![Content::text(
            serde_json::to_string_pretty(&response).unwrap(),
        )])
    }

    /// Send a formatted HTML action summary via SMTP + Wazuh audit event
    pub async fn send_action_summary(
        &self,
        params: SendActionSummaryParams,
    ) -> Result<CallToolResult, McpError> {
        let recipient = params.recipient.as_ref().unwrap_or(&self.admin_email);
        let now = chrono::Utc::now();

        let actions: serde_json::Value =
            serde_json::from_str(&params.actions).unwrap_or_else(|_| json!([]));
        let action_count = actions.as_array().map_or(0, |a| a.len());
        let subject = format!(
            "Wazuh Action Summary: Alert {} ({} actions)",
            params.alert_id, action_count
        );

        // Build a markdown report for the action summary
        let action_md = Self::build_action_summary_markdown(
            &params.alert_id,
            &actions,
            &params.summary,
            &now.to_rfc3339(),
        );

        // Try SMTP email
        let smtp_result = if self.smtp_enabled {
            self.send_smtp_email(recipient, &subject, &action_md, None)
                .await
        } else {
            Err("SMTP not configured".to_string())
        };

        // Wazuh audit event
        let event_payload = json!({
            "integration": self.notification_tag,
            "mcp_report": {
                "type": "action_summary",
                "recipient": recipient,
                "subject": subject,
                "alert_id": params.alert_id,
                "generated_at": now.to_rfc3339(),
                "smtp_sent": smtp_result.is_ok(),
                "action_count": action_count,
            }
        });
        let wazuh_result = self.send_manager_event(event_payload).await;

        let response = json!({
            "status": if smtp_result.is_ok() { "email_sent" } else { "email_failed" },
            "smtp_delivery": match &smtp_result {
                Ok(msg) => json!({"success": true, "message": msg}),
                Err(e) => json!({"success": false, "error": e}),
            },
            "wazuh_audit_event": match &wazuh_result {
                Ok(v) => json!({"success": true, "delivery": v}),
                Err(e) => json!({"success": false, "error": e}),
            },
            "recipient": recipient,
            "alert_id": params.alert_id,
            "action_count": action_count,
            "timestamp": now.to_rfc3339(),
        });

        Self::success_result(vec![Content::text(
            serde_json::to_string_pretty(&response).unwrap(),
        )])
    }

    // ============================================================================
    // SMTP Email Sending
    // ============================================================================

    /// Send a formatted HTML email via SMTP with optional file attachments
    async fn send_smtp_email(
        &self,
        recipient: &str,
        subject: &str,
        markdown_body: &str,
        attachment_paths: Option<&[String]>,
    ) -> Result<String, String> {
        use lettre::message::{Attachment, Message, MultiPart, SinglePart};
        use lettre::transport::smtp::authentication::Credentials;
        use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};

        // Convert markdown to HTML
        let html_body = Self::markdown_to_html_email(markdown_body, subject);

        // Build multipart body: plain text + HTML alternatives
        let alternatives = MultiPart::alternative()
            .singlepart(SinglePart::plain(markdown_body.to_string()))
            .singlepart(SinglePart::html(html_body));

        // Build top-level mixed part (alternatives + attachments)
        let mut email_body = MultiPart::mixed().multipart(alternatives);

        // Attach files if provided
        if let Some(paths) = attachment_paths {
            for path in paths {
                match std::fs::read(path) {
                    Ok(file_bytes) => {
                        let filename = std::path::Path::new(path)
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_else(|| "attachment".to_string());

                        let content_type = if path.ends_with(".csv") {
                            "text/csv".parse().unwrap()
                        } else if path.ends_with(".md") {
                            "text/markdown".parse().unwrap()
                        } else if path.ends_with(".json") {
                            "application/json".parse().unwrap()
                        } else {
                            "application/octet-stream".parse().unwrap()
                        };

                        let attachment =
                            Attachment::new(filename).body(file_bytes, content_type);
                        email_body = email_body.singlepart(attachment);
                    }
                    Err(e) => {
                        tracing::warn!("Could not read attachment file {}: {}", path, e);
                    }
                }
            }
        }

        // Build the email message
        let from_addr = self
            .smtp_from
            .parse()
            .map_err(|e| format!("Invalid SMTP_FROM address '{}': {}", self.smtp_from, e))?;
        let to_addr = recipient
            .parse()
            .map_err(|e| format!("Invalid recipient address '{}': {}", recipient, e))?;

        let email = Message::builder()
            .from(from_addr)
            .to(to_addr)
            .subject(subject)
            .multipart(email_body)
            .map_err(|e| format!("Failed to build email message: {}", e))?;

        // Create SMTP transport
        let creds = Credentials::new(self.smtp_username.clone(), self.smtp_password.clone());

        let mailer = if self.smtp_port == 465 {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&self.smtp_host)
                .map_err(|e| format!("Failed to create SMTP relay: {}", e))?
                .credentials(creds)
                .build()
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&self.smtp_host)
                .map_err(|e| format!("Failed to create SMTP STARTTLS relay: {}", e))?
                .credentials(creds)
                .build()
        };

        // Send the email
        let response = mailer
            .send(email)
            .await
            .map_err(|e| format!("SMTP send failed: {}", e))?;

        Ok(format!(
            "Email sent successfully (SMTP {})",
            response.code()
        ))
    }

    // ============================================================================
    // Markdown to HTML Conversion
    // ============================================================================

    /// Convert markdown content to a styled HTML email document
    fn markdown_to_html_email(markdown: &str, title: &str) -> String {
        use comrak::Options;

        let mut opts = Options::default();
        opts.extension.table = true;
        opts.extension.strikethrough = true;
        opts.extension.autolink = true;
        opts.extension.tasklist = true;
        opts.render.unsafe_ = true;

        let html_fragment = comrak::markdown_to_html(markdown, &opts);

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    line-height: 1.6;
    color: #2d3748;
    max-width: 900px;
    margin: 0 auto;
    padding: 24px;
    background-color: #f7fafc;
  }}
  .email-container {{
    background-color: #ffffff;
    border-radius: 8px;
    padding: 32px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.12);
  }}
  .header {{
    background: linear-gradient(135deg, #1a365d 0%, #2b6cb0 100%);
    color: #ffffff;
    padding: 24px 32px;
    border-radius: 8px 8px 0 0;
    margin: -32px -32px 24px -32px;
  }}
  .header h1 {{
    margin: 0;
    font-size: 22px;
    font-weight: 600;
    border: none;
    color: #ffffff;
    padding: 0;
  }}
  .header .subtitle {{
    margin: 4px 0 0 0;
    font-size: 13px;
    opacity: 0.85;
  }}
  h1 {{
    color: #1a365d;
    font-size: 22px;
    border-bottom: 2px solid #e2e8f0;
    padding-bottom: 8px;
    margin-top: 32px;
  }}
  h2 {{
    color: #2b6cb0;
    font-size: 18px;
    border-bottom: 1px solid #e2e8f0;
    padding-bottom: 6px;
    margin-top: 28px;
  }}
  h3 {{
    color: #2d3748;
    font-size: 15px;
    margin-top: 20px;
  }}
  table {{
    border-collapse: collapse;
    width: 100%;
    margin: 16px 0;
    font-size: 14px;
  }}
  th {{
    background-color: #2b6cb0;
    color: #ffffff;
    padding: 10px 14px;
    text-align: left;
    font-weight: 600;
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }}
  td {{
    border: 1px solid #e2e8f0;
    padding: 8px 14px;
  }}
  tr:nth-child(even) {{
    background-color: #f7fafc;
  }}
  tr:hover {{
    background-color: #ebf4ff;
  }}
  code {{
    background: #edf2f7;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 0.9em;
    font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
    color: #c53030;
  }}
  pre {{
    background: #1a202c;
    color: #e2e8f0;
    padding: 16px;
    border-radius: 6px;
    overflow-x: auto;
    font-size: 13px;
    line-height: 1.5;
  }}
  pre code {{
    background: none;
    color: inherit;
    padding: 0;
  }}
  ul, ol {{
    padding-left: 24px;
  }}
  li {{
    margin-bottom: 4px;
  }}
  strong {{
    color: #1a202c;
  }}
  blockquote {{
    border-left: 4px solid #2b6cb0;
    margin: 16px 0;
    padding: 8px 16px;
    background: #ebf8ff;
    border-radius: 0 4px 4px 0;
  }}
  hr {{
    border: none;
    border-top: 2px solid #e2e8f0;
    margin: 24px 0;
  }}
  .footer {{
    margin-top: 32px;
    padding: 16px 0;
    border-top: 2px solid #e2e8f0;
    font-size: 12px;
    color: #718096;
    text-align: center;
  }}
  .badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 12px;
    font-weight: 600;
  }}
  .badge-critical {{ background: #fed7d7; color: #c53030; }}
  .badge-high {{ background: #feebc8; color: #c05621; }}
  .badge-medium {{ background: #fefcbf; color: #975a16; }}
  .badge-low {{ background: #c6f6d5; color: #276749; }}
</style>
</head>
<body>
<div class="email-container">
  <div class="header">
    <h1>Wazuh SOC Report</h1>
    <p class="subtitle">{title}</p>
  </div>
  {html_fragment}
  <div class="footer">
    Generated by <strong>MCP Server Wazuh</strong> &mdash; Automated SOC Analysis Engine
  </div>
</div>
</body>
</html>"#,
            title = Self::html_escape(title),
            html_fragment = html_fragment,
        )
    }

    /// Simple HTML entity escaping for title text
    fn html_escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    }

    // ============================================================================
    // Action Summary Markdown Builder
    // ============================================================================

    fn build_action_summary_markdown(
        alert_id: &str,
        actions: &serde_json::Value,
        summary: &str,
        timestamp: &str,
    ) -> String {
        let mut md = String::new();
        md.push_str(&format!("# Wazuh Action Summary\n\n"));
        md.push_str(&format!("**Alert ID:** {}\n\n", alert_id));
        md.push_str(&format!("**Generated:** {}\n\n", timestamp));
        md.push_str(&format!("## Summary\n\n{}\n\n", summary));

        if let Some(actions_arr) = actions.as_array() {
            md.push_str("## Actions Taken\n\n");
            md.push_str("| # | Action | Target | Agent | Status | Duration |\n");
            md.push_str("|---|--------|--------|-------|--------|----------|\n");

            for (i, action) in actions_arr.iter().enumerate() {
                let action_type = action
                    .get("action_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-");
                let target = action
                    .get("target")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-");
                let agent_id = action
                    .get("agent_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-");
                let status = action
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-");
                let duration_ms = action
                    .get("duration_ms")
                    .and_then(|v| v.as_u64())
                    .map(|ms| format!("{}ms", ms))
                    .unwrap_or_else(|| "-".to_string());

                md.push_str(&format!(
                    "| {} | {} | {} | {} | {} | {} |\n",
                    i + 1,
                    action_type,
                    target,
                    agent_id,
                    status,
                    duration_ms,
                ));
            }

            md.push_str("\n### Action Details\n\n");
            for (i, action) in actions_arr.iter().enumerate() {
                let action_type = action
                    .get("action_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-");
                let reason = action
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-");
                let result = action
                    .get("execution_result")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-");
                md.push_str(&format!(
                    "**{}. {}**\n- **Reason:** {}\n- **Result:** {}\n\n",
                    i + 1,
                    action_type,
                    reason,
                    result,
                ));
            }
        }

        md
    }

    // ============================================================================
    // Wazuh Event API (audit logging - secondary)
    // ============================================================================

    async fn send_manager_event(
        &self,
        event_payload: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(!self.verify_ssl)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .user_agent("mcp-server-wazuh/notifications")
            .build()
            .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

        let token = self.authenticate_wazuh(&client).await?;
        let endpoint = format!("{}/events", self.wazuh_api_base_url);
        let payload = json!({
            "events": [event_payload.to_string()]
        });

        let response = client
            .post(&endpoint)
            .bearer_auth(token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Failed to call Wazuh /events API: {}", e))?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        if !status.is_success() {
            return Err(format!(
                "Wazuh /events API returned {}: {}",
                status.as_u16(),
                body
            ));
        }

        Ok(json!({
            "endpoint": endpoint,
            "http_status": status.as_u16(),
            "body": body,
        }))
    }

    async fn authenticate_wazuh(&self, client: &reqwest::Client) -> Result<String, String> {
        if self.wazuh_api_password.is_empty() {
            return Err(
                "WAZUH_API_PASSWORD is empty; required for manager notification delivery"
                    .to_string(),
            );
        }

        let auth_endpoint = format!(
            "{}/security/user/authenticate?raw=true",
            self.wazuh_api_base_url
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
}

impl ToolModule for NotificationTools {}
