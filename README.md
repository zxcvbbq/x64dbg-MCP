# x64dbg MCP

Use x64dbg from Claude Code or Codex through MCP tools. The client plugin downloads the version-pinned prebuilt MCP server from its GitHub Release on first launch; Rust is only needed when building from source.

## Install

Requires Windows x64 and x64dbg (x64 or x32), plus Claude Code or Codex. Rust is not required.

For Claude Code:

```powershell
claude plugin marketplace add zxcvbbq/x64dbg-MCP
claude plugin install x64dbg-mcp@zxcvbbq
```

For Codex:

```powershell
codex plugin marketplace add zxcvbbq/x64dbg-MCP
codex plugin add x64dbg-mcp@x64dbg-mcp
```

Download the matching adapter from the [Releases tab](https://github.com/zxcvbbq/x64dbg-MCP/releases) and copy it into the `plugins` folder next to the debugger executable:

- x64dbg: [x64dbg_mcp-x64.dp64](https://github.com/zxcvbbq/x64dbg-MCP/releases/latest/download/x64dbg_mcp-x64.dp64)
- x32dbg: [x64dbg_mcp-x86.dp32](https://github.com/zxcvbbq/x64dbg-MCP/releases/latest/download/x64dbg_mcp-x86.dp32)

Restart x64dbg after copying the adapter, then restart Claude Code or Codex. When the MCP plugin starts, it downloads the versioned x64 server executable to `%LOCALAPPDATA%\x64dbg-MCP` and verifies its SHA-256 checksum. No separate installer or Rust toolchain is needed.

## Tools

- `x64dbg_status`: report whether a debuggee is open and running.
- `x64dbg_evaluate`: evaluate an x64dbg expression.
- `x64dbg_disassemble`: disassemble 1–128 instructions at an address or expression.
- `x64dbg_read_memory`: read 1–4096 bytes from the debuggee.
- `x64dbg_write_memory`: write 1–4096 bytes to the debuggee.
- `x64dbg_get_registers`: read general-purpose registers, flags, and segment registers.
- `x64dbg_get_stack`: read 1–64 pointer-sized values from the current stack pointer.
- `x64dbg_list_breakpoints`: list the session's breakpoints.
- `x64dbg_set_breakpoint` / `x64dbg_remove_breakpoint`: set or remove a software breakpoint.
- `x64dbg_execute_command`: execute an x64dbg command; the tool returns a success flag, not command log output.

Memory writes and x64dbg commands can change the debuggee or debugger state. Review tool calls that make changes. The adapter accepts unauthenticated connections from localhost on port `42070`, so other local processes can also access the active debug session. Only one x64dbg instance can use that port at a time.

## Build from source

Requires Windows 10 or later, Rust stable 1.88+, and x64dbg. Build the MCP server and x64 adapter with:

```powershell
cargo build --release --locked
```

Build the x32 adapter with:

```powershell
rustup target add i686-pc-windows-msvc
cargo build --release --lib --locked --target i686-pc-windows-msvc
```

Copy `target\release\x64dbg_plugin.dll` to the x64dbg `plugins` directory as `x64dbg_mcp.dp64`. For x32dbg, copy `target\i686-pc-windows-msvc\release\x64dbg_plugin.dll` as `x64dbg_mcp.dp32`.
