#[cfg(windows)]
mod plugin {
    use serde_json::{Value, json};
    use std::{
        ffi::{CString, c_char, c_int, c_void},
        io::{BufRead, BufReader, Read, Write},
        mem::transmute_copy,
        net::{TcpListener, TcpStream},
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{
            Mutex, OnceLock,
            atomic::{AtomicBool, Ordering},
        },
        thread::{self, JoinHandle},
        time::Duration,
    };

    // shortcut: one x64dbg instance per port, make this configurable for multi-instance support.
    const PORT: u16 = 42070;
    const MAX_REQUEST: u64 = 64 * 1024;
    static RUNNING: AtomicBool = AtomicBool::new(false);
    static API: OnceLock<BridgeApi> = OnceLock::new();
    static SERVER_THREAD: Mutex<Option<JoinHandle<()>>> = Mutex::new(None);

    type Eval = unsafe extern "C" fn(*const c_char, *mut bool) -> usize;
    type MemRead = unsafe extern "C" fn(usize, *mut c_void, usize) -> bool;
    type DisasmAt = unsafe extern "C" fn(usize, *mut DisasmInstr);
    type Command = unsafe extern "C" fn(*const c_char) -> bool;
    type DebugState = unsafe extern "C" fn() -> bool;

    struct BridgeApi {
        eval: Eval,
        mem_read: MemRead,
        disasm_at: DisasmAt,
        command: Command,
        is_debugging: DebugState,
        is_running: DebugState,
    }

    #[repr(C)]
    struct DisasmArg {
        kind: c_int,
        segment: c_int,
        mnemonic: [c_char; 64],
        constant: usize,
        value: usize,
        memvalue: usize,
    }

    #[repr(C)]
    struct DisasmInstr {
        instruction: [c_char; 64],
        kind: c_int,
        arg_count: c_int,
        instruction_size: c_int,
        args: [DisasmArg; 3],
    }

    #[repr(C)]
    pub struct PluginInit {
        plugin_handle: c_int,
        sdk_version: c_int,
        plugin_version: c_int,
        plugin_name: [c_char; 256],
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetModuleHandleW(module: *const u16) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    }

    unsafe fn bridge_fn<T: Copy>(module: *mut c_void, name: &'static [u8]) -> Result<T, String> {
        let address = unsafe { GetProcAddress(module, name.as_ptr()) };
        if address.is_null() {
            return Err(format!(
                "x64dbg bridge is missing {}",
                String::from_utf8_lossy(&name[..name.len() - 1])
            ));
        }
        Ok(unsafe { transmute_copy(&address) })
    }

    unsafe fn load_bridge() -> Result<BridgeApi, String> {
        let bridge_dll = if usize::BITS == 64 {
            "x64bridge.dll\0"
        } else {
            "x32bridge.dll\0"
        };
        let module_name: Vec<u16> = bridge_dll.encode_utf16().collect();
        let module = unsafe { GetModuleHandleW(module_name.as_ptr()) };
        if module.is_null() {
            return Err(format!("{bridge_dll} is not loaded"));
        }
        Ok(BridgeApi {
            eval: unsafe { bridge_fn(module, b"DbgEval\0")? },
            mem_read: unsafe { bridge_fn(module, b"DbgMemRead\0")? },
            disasm_at: unsafe { bridge_fn(module, b"DbgDisasmAt\0")? },
            command: unsafe { bridge_fn(module, b"DbgCmdExecDirect\0")? },
            is_debugging: unsafe { bridge_fn(module, b"DbgIsDebugging\0")? },
            is_running: unsafe { bridge_fn(module, b"DbgIsRunning\0")? },
        })
    }

    fn api() -> Result<&'static BridgeApi, String> {
        API.get()
            .ok_or_else(|| "x64dbg MCP plugin is not initialized".to_owned())
    }

    fn text_param<'a>(params: &'a Value, name: &str, max_len: usize) -> Result<&'a str, String> {
        let value = params
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("'{name}' must be a string"))?;
        if value.is_empty() || value.len() > max_len {
            return Err(format!("'{name}' must contain 1 to {max_len} bytes"));
        }
        Ok(value)
    }

    fn evaluate(api: &BridgeApi, expression: &str) -> Result<usize, String> {
        let expression =
            CString::new(expression).map_err(|_| "expression contains NUL".to_owned())?;
        let mut success = false;
        let value = unsafe { (api.eval)(expression.as_ptr(), &mut success) };
        success
            .then_some(value)
            .ok_or_else(|| "x64dbg could not evaluate the expression".to_owned())
    }

    fn dispatch(request: &Value) -> Result<Value, String> {
        let api = api()?;
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(|| "request is missing a method".to_owned())?;
        let params = request.get("params").unwrap_or(&Value::Null);

        match method {
            "status" => Ok(json!({
                "debugging": unsafe { (api.is_debugging)() },
                "running": unsafe { (api.is_running)() }
            })),
            "evaluate" => {
                let value = evaluate(api, text_param(params, "expression", 1024)?)?;
                Ok(json!({ "value": format!("0x{value:X}"), "decimal": value }))
            }
            "disassemble" => {
                let mut address = evaluate(api, text_param(params, "address", 256)?)?;
                let count = params.get("count").and_then(Value::as_u64).unwrap_or(16);
                if !(1..=128).contains(&count) {
                    return Err("count must be between 1 and 128".to_owned());
                }
                if !unsafe { (api.is_debugging)() } {
                    return Err("x64dbg has no active debuggee".to_owned());
                }

                let mut instructions = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    let mut instruction: DisasmInstr = unsafe { std::mem::zeroed() };
                    unsafe { (api.disasm_at)(address, &mut instruction) };
                    if instruction.instruction_size <= 0 {
                        return Err(format!("x64dbg could not disassemble 0x{address:X}"));
                    }
                    let text = instruction
                        .instruction
                        .iter()
                        .take_while(|&&c| c != 0)
                        .map(|&c| c as u8)
                        .collect::<Vec<_>>();
                    instructions.push(json!({
                        "address": format!("0x{address:X}"),
                        "instruction": String::from_utf8_lossy(&text),
                        "size": instruction.instruction_size
                    }));
                    address = address
                        .checked_add(instruction.instruction_size as usize)
                        .ok_or_else(|| "disassembly address overflow".to_owned())?;
                }
                Ok(json!({ "instructions": instructions }))
            }
            "read_memory" => {
                if !unsafe { (api.is_debugging)() } {
                    return Err("x64dbg has no active debuggee".to_owned());
                }
                let address = evaluate(api, text_param(params, "address", 256)?)?;
                let length = params
                    .get("length")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| "'length' must be an integer".to_owned())?;
                if !(1..=4096).contains(&length) {
                    return Err("length must be between 1 and 4096".to_owned());
                }
                let mut bytes = vec![0; length as usize];
                if !unsafe { (api.mem_read)(address, bytes.as_mut_ptr().cast(), bytes.len()) } {
                    return Err(format!("x64dbg could not read memory at 0x{address:X}"));
                }
                let hex = bytes
                    .iter()
                    .map(|byte| format!("{byte:02X}"))
                    .collect::<String>();
                Ok(json!({ "address": format!("0x{address:X}"), "length": length, "bytes": hex }))
            }
            "execute_command" => {
                let command = text_param(params, "command", 4096)?;
                let command_c =
                    CString::new(command).map_err(|_| "command contains NUL".to_owned())?;
                let succeeded = unsafe { (api.command)(command_c.as_ptr()) };
                Ok(json!({ "success": succeeded }))
            }
            _ => Err(format!("unknown x64dbg method '{method}'")),
        }
    }

    fn serve_connection(mut stream: TcpStream) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let mut request_line = String::new();
        let mut reader = BufReader::new(match stream.try_clone() {
            Ok(stream) => stream,
            Err(_) => return,
        });
        if reader
            .by_ref()
            .take(MAX_REQUEST)
            .read_line(&mut request_line)
            .is_err()
            || request_line.len() as u64 >= MAX_REQUEST
            || !request_line.ends_with('\n')
        {
            let _ = writeln!(stream, "{{\"error\":\"request too large or incomplete\"}}");
            return;
        }
        let response = match serde_json::from_str::<Value>(&request_line) {
            Ok(request) => match dispatch(&request) {
                Ok(result) => json!({ "result": result }),
                Err(error) => json!({ "error": error }),
            },
            Err(error) => json!({ "error": format!("invalid JSON: {error}") }),
        };
        let _ = serde_json::to_writer(&mut stream, &response);
        let _ = stream.write_all(b"\n");
    }

    fn serve(listener: TcpListener) {
        while RUNNING.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _)) => serve_connection(stream),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn pluginit(init: *mut PluginInit) -> bool {
        if init.is_null() || API.get().is_some() {
            return false;
        }
        let bridge = match unsafe { load_bridge() } {
            Ok(bridge) => bridge,
            Err(_) => return false,
        };
        if API.set(bridge).is_err() {
            return false;
        }
        let listener = match TcpListener::bind(("127.0.0.1", PORT)) {
            Ok(listener) => listener,
            Err(_) => return false,
        };
        if listener.set_nonblocking(true).is_err() {
            return false;
        }
        let expected_size = if usize::BITS == 64 { 368 } else { 328 };
        if std::mem::size_of::<DisasmInstr>() != expected_size {
            return false;
        }
        RUNNING.store(true, Ordering::Release);
        let handle = match thread::Builder::new()
            .name("x64dbg-mcp".to_owned())
            .spawn(move || {
                let _ = catch_unwind(AssertUnwindSafe(|| serve(listener)));
            }) {
            Ok(handle) => handle,
            Err(_) => {
                RUNNING.store(false, Ordering::Release);
                return false;
            }
        };
        if let Ok(mut thread) = SERVER_THREAD.lock() {
            *thread = Some(handle);
        } else {
            RUNNING.store(false, Ordering::Release);
            return false;
        }

        let init = unsafe { &mut *init };
        init.sdk_version = 1;
        init.plugin_version = 1;
        init.plugin_name.fill(0);
        let name = b"x64dbg-mcp\0";
        for (destination, source) in init.plugin_name.iter_mut().zip(name) {
            *destination = *source as c_char;
        }
        true
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn plugstop() -> bool {
        RUNNING.store(false, Ordering::Release);
        if let Ok(mut thread) = SERVER_THREAD.lock() {
            if let Some(handle) = thread.take() {
                let _ = handle.join();
            }
        }
        true
    }
}
