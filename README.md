# x64dbg MCP

A Rust MCP server for Claude Code and Codex that connects to a running x64dbg session. A small x64dbg plugin exposes the debugger bridge on localhost; the MCP server provides stdio tools to the AI client.

## Requirements

- Windows 10 or later
- x64dbg (x64 or x32)
- Rust stable 1.88 or later, with Cargo on `PATH`
- Claude Code or Codex with plugin support

## Install in Claude Code

```powershell
claude plugin marketplace add zxcvbbq/x64dbg-MCP
claude plugin install x64dbg-mcp@zxcvbbq
```

## Install in Codex

```powershell
codex plugin marketplace add zxcvbbq/x64dbg-MCP
codex plugin add x64dbg-mcp@zxcvbbq
```

The first MCP server launch builds the Rust executable from the installed plugin source.

## Install the x64dbg adapter

Build the adapter from this repository:

```powershell
cargo build --release --lib --locked
```

Copy the DLL into the `plugins` directory beside `x64dbg.exe`, renaming it to the x64dbg plugin extension:

```powershell
$X64DBG_DIR = 'C:\path\to\x64dbg\release\x64'
New-Item -ItemType Directory -Force "$X64DBG_DIR\plugins" | Out-Null
Copy-Item .\target\release\x64dbg_plugin.dll "$X64DBG_DIR\plugins\x64dbg_mcp.dp64"
```

For x32dbg, build its 32-bit plugin and copy it beside `x32dbg.exe`:

```powershell
rustup target add i686-pc-windows-msvc
cargo build --release --lib --locked --target i686-pc-windows-msvc
$X32DBG_DIR = 'C:\path\to\x64dbg\release\x32'
New-Item -ItemType Directory -Force "$X32DBG_DIR\plugins" | Out-Null
Copy-Item .\target\i686-pc-windows-msvc\release\x64dbg_plugin.dll "$X32DBG_DIR\plugins\x64dbg_mcp.dp32"
```

Restart x64dbg after copying the adapter. Keep x64dbg open while using the MCP tools. The adapter listens on `127.0.0.1:42070`; another x64dbg instance cannot use that port at the same time.

## Tools

- `x64dbg_status`: report whether a debuggee is open and running.
- `x64dbg_evaluate`: evaluate an x64dbg expression.
- `x64dbg_disassemble`: disassemble 1–128 instructions at an address or expression.
- `x64dbg_read_memory`: read 1–4096 bytes from the debuggee.
- `x64dbg_execute_command`: execute an x64dbg command. Commands may change debugger or target state; the tool returns a success flag, not the command's log output.

The adapter accepts connections only from localhost and has no authentication. Other local processes running as your user can also send debugger requests.

## Build and run the MCP server manually

```powershell
cargo run --release --locked
```

The server communicates over standard input and output and expects the x64dbg adapter to be loaded.
