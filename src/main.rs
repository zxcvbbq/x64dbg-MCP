use rmcp::{
    ServiceExt, handler::server::wrapper::Parameters, schemars, tool, tool_router, transport::stdio,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
    time::Duration,
};

const PLUGIN_PORT: u16 = 42070;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct EvaluateParams {
    /// An x64dbg expression, such as "$cip" or "module+0x120".
    expression: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct DisassembleParams {
    /// Starting address or x64dbg address expression.
    address: String,
    /// Number of instructions to return, from 1 through 128 (default 16).
    count: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ReadMemoryParams {
    /// Starting address or x64dbg address expression.
    address: String,
    /// Number of bytes to read, from 1 through 4096.
    length: u32,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ExecuteCommandParams {
    /// An x64dbg command. Commands can change debugger or target state.
    command: String,
}

fn plugin_call(method: &str, params: Value) -> Result<String, String> {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), PLUGIN_PORT);
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2)).map_err(|error| {
        format!(
            "Cannot reach the x64dbg plugin at {address}. Install x64dbg_mcp.dp64 or .dp32 and restart x64dbg ({error})."
        )
    })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|error| error.to_string())?;
    serde_json::to_writer(&mut stream, &json!({ "method": method, "params": params }))
        .map_err(|error| error.to_string())?;
    stream.write_all(b"\n").map_err(|error| error.to_string())?;

    let mut response = String::new();
    BufReader::new(stream)
        .take(1024 * 1024)
        .read_line(&mut response)
        .map_err(|error| error.to_string())?;
    if response.is_empty() || response.len() >= 1024 * 1024 || !response.ends_with('\n') {
        return Err("x64dbg plugin returned an invalid or oversized response".to_owned());
    }
    let response: Value = serde_json::from_str(&response).map_err(|error| error.to_string())?;
    if let Some(error) = response.get("error").and_then(Value::as_str) {
        return Err(error.to_owned());
    }
    response
        .get("result")
        .map(Value::to_string)
        .ok_or_else(|| "x64dbg plugin response is missing a result".to_owned())
}

#[derive(Clone)]
struct X64Dbg;

#[tool_router(server_handler)]
impl X64Dbg {
    #[tool(description = "Report whether x64dbg has a debuggee and whether it is running.")]
    fn x64dbg_status(&self) -> Result<String, String> {
        plugin_call("status", json!({}))
    }

    #[tool(description = "Evaluate an x64dbg expression and return its value.")]
    fn x64dbg_evaluate(
        &self,
        Parameters(params): Parameters<EvaluateParams>,
    ) -> Result<String, String> {
        plugin_call("evaluate", json!({ "expression": params.expression }))
    }

    #[tool(description = "Disassemble 1 to 128 instructions at an address or x64dbg expression.")]
    fn x64dbg_disassemble(
        &self,
        Parameters(params): Parameters<DisassembleParams>,
    ) -> Result<String, String> {
        plugin_call(
            "disassemble",
            json!({ "address": params.address, "count": params.count.unwrap_or(16) }),
        )
    }

    #[tool(
        description = "Read 1 to 4096 bytes from the active debuggee's memory and return them as hex."
    )]
    fn x64dbg_read_memory(
        &self,
        Parameters(params): Parameters<ReadMemoryParams>,
    ) -> Result<String, String> {
        plugin_call(
            "read_memory",
            json!({ "address": params.address, "length": params.length }),
        )
    }

    #[tool(
        description = "Execute an x64dbg command. This can change debugger or target state; output is limited to a success flag."
    )]
    fn x64dbg_execute_command(
        &self,
        Parameters(params): Parameters<ExecuteCommandParams>,
    ) -> Result<String, String> {
        plugin_call("execute_command", json!({ "command": params.command }))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    X64Dbg.serve(stdio()).await?.waiting().await?;
    Ok(())
}
