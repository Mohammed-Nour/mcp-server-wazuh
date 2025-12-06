//! Tests for MCP protocol communication via HTTP transport
//!
//! These tests verify the Streamable HTTP transport implementation.
//! Run with: cargo test --features http --test mcp_http_test

use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::time::sleep;
use serde_json::{json, Value};

struct McpHttpServer {
    child: Child,
    base_url: String,
    #[allow(dead_code)]
    port: u16,
}

impl McpHttpServer {
    async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        // Find an available port
        let port = portpicker::pick_unused_port().unwrap_or(18080);
        let base_url = format!("http://127.0.0.1:{}", port);

        let child = Command::new("cargo")
            .args([
                "run",
                "--features", "http",
                "--bin", "mcp-server-wazuh",
                "--",
                "--transport", "http",
                "--host", "127.0.0.1",
                "--port", &port.to_string(),
            ])
            .env("WAZUH_API_HOST", "nonexistent.example.com")
            .env("WAZUH_API_PORT", "9999")
            .env("WAZUH_API_USER", "test")
            .env("WAZUH_API_PASS", "test")
            .env("WAZUH_INDEXER_HOST", "nonexistent.example.com")
            .env("WAZUH_INDEXER_PORT", "8888")
            .env("WAZUH_INDEXER_USER", "test")
            .env("WAZUH_INDEXER_PASS", "test")
            .env("VERIFY_SSL", "false")
            .env("RUST_LOG", "error")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;

        // Wait for server to start
        let server = McpHttpServer { child, base_url: base_url.clone(), port };

        // Poll until the server is ready (max 30 seconds for cargo build + startup)
        let client = reqwest::Client::new();
        let max_retries = 60;
        for i in 0..max_retries {
            sleep(Duration::from_millis(500)).await;

            // Try to connect to the server - use both Accept headers
            let result = client
                .post(format!("{}/mcp", base_url))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .json(&json!({
                    "jsonrpc": "2.0",
                    "id": 0,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "startup-check", "version": "1.0.0"}
                    }
                }))
                .send()
                .await;

            if let Ok(resp) = result {
                if resp.status().is_success() {
                    return Ok(server);
                }
            }

            if i % 10 == 0 {
                eprintln!("Waiting for HTTP server to start... (attempt {}/{})", i + 1, max_retries);
            }
        }

        Err("Server failed to start within timeout".into())
    }

    fn url(&self) -> &str {
        &self.base_url
    }
}

impl Drop for McpHttpServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct McpHttpClient {
    client: reqwest::Client,
    base_url: String,
    session_id: Option<String>,
}

impl McpHttpClient {
    fn new(base_url: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.to_string(),
            session_id: None,
        }
    }

    async fn send_request(&mut self, message: &Value) -> Result<Value, Box<dyn std::error::Error>> {
        let mut request = self.client
            .post(format!("{}/mcp", self.base_url))
            .header("Content-Type", "application/json")
            // MCP Streamable HTTP spec requires accepting both JSON and SSE
            .header("Accept", "application/json, text/event-stream");

        // Add session ID header if we have one
        if let Some(session_id) = &self.session_id {
            request = request.header("Mcp-Session-Id", session_id);
        }

        let response = request.json(message).send().await?;

        // Check for error status
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(format!("HTTP error {}: {}", status, text).into());
        }

        // Extract session ID from response headers if present
        if let Some(session_id) = response.headers().get("Mcp-Session-Id") {
            self.session_id = Some(session_id.to_str()?.to_string());
        }

        let text = response.text().await?;

        // Handle SSE format - the response is in SSE format with "data:" prefix
        let json_str = text.lines()
            .filter(|line| line.starts_with("data:"))
            .map(|line| line.trim_start_matches("data:").trim())
            .filter(|s| !s.is_empty())
            .next()
            .ok_or_else(|| format!("No JSON data found in SSE response: {}", text))?;

        let response: Value = serde_json::from_str(json_str)?;
        Ok(response)
    }

    async fn initialize(&mut self) -> Result<Value, Box<dyn std::error::Error>> {
        let init_request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }
        });

        self.send_request(&init_request).await
    }

    async fn send_initialized_notification(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let notification = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });

        // Notifications don't expect a response, but we send it anyway
        let mut request = self.client
            .post(format!("{}/mcp", self.base_url))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream");

        if let Some(session_id) = &self.session_id {
            request = request.header("Mcp-Session-Id", session_id);
        }

        let _ = request.json(&notification).send().await?;
        Ok(())
    }

    async fn list_tools(&mut self) -> Result<Value, Box<dyn std::error::Error>> {
        let request = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        });

        self.send_request(&request).await
    }
}

#[cfg(feature = "http")]
mod http_tests {
    use super::*;

    // Helper to check if we should skip HTTP tests
    fn should_skip() -> bool {
        std::env::var("SKIP_HTTP_TESTS").is_ok()
    }

    #[tokio::test]
    async fn test_http_protocol_initialization() -> Result<(), Box<dyn std::error::Error>> {
        if should_skip() {
            eprintln!("Skipping HTTP test (SKIP_HTTP_TESTS is set)");
            return Ok(());
        }

        let server = McpHttpServer::start().await?;
        let mut client = McpHttpClient::new(server.url());

        let response = client.initialize().await?;

        // Verify JSON-RPC 2.0 compliance
        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 1);
        assert!(response["result"].is_object(), "Expected result object, got: {:?}", response);
        assert!(response["error"].is_null(), "Unexpected error: {:?}", response["error"]);

        // Verify MCP initialize response structure
        let result = &response["result"];
        // Protocol version depends on rmcp library version - accept valid MCP versions
        let protocol_version = result["protocolVersion"].as_str().unwrap();
        assert!(
            protocol_version.starts_with("202"),
            "Expected MCP protocol version (e.g., 2025-03-26), got: {}",
            protocol_version
        );
        assert!(result["capabilities"].is_object());
        assert!(result["serverInfo"].is_object());

        // Verify server info
        let server_info = &result["serverInfo"];
        assert!(server_info["name"].is_string());
        assert!(server_info["version"].is_string());

        // Verify session ID was set
        assert!(client.session_id.is_some(), "Session ID should be set after initialization");

        Ok(())
    }

    #[tokio::test]
    async fn test_http_tools_list() -> Result<(), Box<dyn std::error::Error>> {
        if should_skip() {
            eprintln!("Skipping HTTP test (SKIP_HTTP_TESTS is set)");
            return Ok(());
        }

        let server = McpHttpServer::start().await?;
        let mut client = McpHttpClient::new(server.url());

        // Initialize first
        client.initialize().await?;
        client.send_initialized_notification().await?;

        // Request tools list
        let response = client.list_tools().await?;

        // Verify response structure
        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 2);
        assert!(response["result"].is_object(), "Expected result object, got: {:?}", response);

        let result = &response["result"];
        assert!(result["tools"].is_array(), "Expected tools array");

        let tools = result["tools"].as_array().unwrap();
        assert!(!tools.is_empty(), "Tools list should not be empty");

        // Verify tool structure
        for tool in tools {
            assert!(tool["name"].is_string(), "Tool should have name");
            assert!(tool["description"].is_string(), "Tool should have description");
            assert!(tool["inputSchema"].is_object(), "Tool should have inputSchema");
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_http_session_management() -> Result<(), Box<dyn std::error::Error>> {
        if should_skip() {
            eprintln!("Skipping HTTP test (SKIP_HTTP_TESTS is set)");
            return Ok(());
        }

        let server = McpHttpServer::start().await?;
        let mut client = McpHttpClient::new(server.url());

        // Initialize and get session ID
        client.initialize().await?;
        let session_id = client.session_id.clone();
        assert!(session_id.is_some(), "Should receive session ID on init");

        client.send_initialized_notification().await?;

        // Subsequent requests should work with the same session
        let response = client.list_tools().await?;
        assert!(response["result"].is_object(), "Should get valid response with session");

        Ok(())
    }

    #[tokio::test]
    async fn test_http_multiple_requests() -> Result<(), Box<dyn std::error::Error>> {
        if should_skip() {
            eprintln!("Skipping HTTP test (SKIP_HTTP_TESTS is set)");
            return Ok(());
        }

        let server = McpHttpServer::start().await?;
        let mut client = McpHttpClient::new(server.url());

        // Initialize
        client.initialize().await?;
        client.send_initialized_notification().await?;

        // Send multiple requests
        for i in 0..3 {
            let request = json!({
                "jsonrpc": "2.0",
                "id": 10 + i,
                "method": "tools/list",
                "params": {}
            });

            let response = client.send_request(&request).await?;
            assert_eq!(response["id"], 10 + i);
            assert!(response["result"].is_object());
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_http_content_type_headers() -> Result<(), Box<dyn std::error::Error>> {
        if should_skip() {
            eprintln!("Skipping HTTP test (SKIP_HTTP_TESTS is set)");
            return Ok(());
        }

        let server = McpHttpServer::start().await?;
        let client = reqwest::Client::new();

        // Test that server accepts application/json with both Accept types
        let response = client
            .post(format!("{}/mcp", server.url()))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1.0"}
                }
            }))
            .send()
            .await?;

        assert!(response.status().is_success(), "Expected success status, got: {}", response.status());

        Ok(())
    }
}

// Port picker utility for tests
mod portpicker {
    use std::net::TcpListener;

    pub fn pick_unused_port() -> Option<u16> {
        // Try to bind to port 0, which lets the OS assign an available port
        TcpListener::bind("127.0.0.1:0")
            .ok()
            .and_then(|listener| listener.local_addr().ok())
            .map(|addr| addr.port())
    }
}
