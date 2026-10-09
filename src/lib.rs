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
    type MemWrite = unsafe extern "C" fn(usize, *const c_void, usize) -> bool;
    type DisasmAt = unsafe extern "C" fn(usize, *mut DisasmInstr);
    type Command = unsafe extern "C" fn(*const c_char) -> bool;
    type DebugState = unsafe extern "C" fn() -> bool;
    type BpList = unsafe extern "C" fn(c_int, *mut BpMap) -> c_int;
    type BridgeFree = unsafe extern "C" fn(*mut c_void);

    struct BridgeApi {
        eval: Eval,
        mem_read: MemRead,
        mem_write: MemWrite,
        disasm_at: DisasmAt,
        command: Command,
        is_debugging: DebugState,
        is_running: DebugState,
        bp_list: BpList,
        bridge_free: BridgeFree,
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
    struct BridgeBp {
        kind: c_int,
        address: usize,
        enabled: bool,
        singleshoot: bool,
        active: bool,
        name: [c_char; 256],
        module: [c_char; 256],
        slot: u16,
        type_ex: u8,
        hw_size: u8,
        hit_count: u32,
        fast_resume: bool,
        silent: bool,
        break_condition: [c_char; 256],
        log_text: [c_char; 256],
        log_condition: [c_char; 256],
        command_text: [c_char; 256],
        command_condition: [c_char; 256],
    }

    #[repr(C)]
    #[derive(Default)]
    struct BpMap {
        count: c_int,
        bp: *mut BridgeBp,
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
            mem_write: unsafe { bridge_fn(module, b"DbgMemWrite\0")? },
            disasm_at: unsafe { bridge_fn(module, b"DbgDisasmAt\0")? },
            command: unsafe { bridge_fn(module, b"DbgCmdExecDirect\0")? },
            is_debugging: unsafe { bridge_fn(module, b"DbgIsDebugging\0")? },
            is_running: unsafe { bridge_fn(module, b"DbgIsRunning\0")? },
            bp_list: unsafe { bridge_fn(module, b"DbgGetBpList\0")? },
            bridge_free: unsafe { bridge_fn(module, b"BridgeFree\0")? },
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

    fn c_text(value: &[c_char]) -> String {
        let end = value
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(value.len());
        String::from_utf8_lossy(
            &value[..end]
                .iter()
                .map(|&byte| byte as u8)
                .collect::<Vec<_>>(),
        )
        .into_owned()
    }

    fn stack_addresses(start: usize, count: u64) -> Result<Vec<usize>, String> {
        if !(1..=64).contains(&count) {
            return Err("count must be between 1 and 64".to_owned());
        }
        (0..count)
            .map(|index| {
                start
                    .checked_add(index as usize * std::mem::size_of::<usize>())
                    .ok_or_else(|| "stack address overflow".to_owned())
            })
            .collect()
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
            "get_registers" => {
                if !unsafe { (api.is_debugging)() } {
                    return Err("x64dbg has no active debuggee".to_owned());
                }
                let names: &[&str] = if usize::BITS == 64 {
                    &[
                        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip", "r8", "r9",
                        "r10", "r11", "r12", "r13", "r14", "r15", "eflags", "cs", "ss", "ds", "es",
                        "fs", "gs",
                    ]
                } else {
                    &[
                        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "eflags",
                        "cs", "ss", "ds", "es", "fs", "gs",
                    ]
                };
                let mut registers = serde_json::Map::new();
                for &name in names {
                    if let Ok(value) = evaluate(api, name) {
                        registers.insert(name.to_owned(), json!(format!("0x{value:X}")));
                    }
                }
                if registers.is_empty() {
                    return Err("x64dbg could not read the register context".to_owned());
                }
                Ok(json!({
                    "architecture": if usize::BITS == 64 { "x64" } else { "x86" },
                    "registers": registers
                }))
            }
            "get_stack" => {
                if !unsafe { (api.is_debugging)() } {
                    return Err("x64dbg has no active debuggee".to_owned());
                }
                let count = params.get("count").and_then(Value::as_u64).unwrap_or(16);
                let start = evaluate(api, "csp")?;
                let addresses = stack_addresses(start, count)?;
                let mut bytes = vec![0; addresses.len() * std::mem::size_of::<usize>()];
                if !unsafe { (api.mem_read)(start, bytes.as_mut_ptr().cast(), bytes.len()) } {
                    return Err(format!("x64dbg could not read stack memory at 0x{start:X}"));
                }
                let values = bytes
                    .chunks_exact(std::mem::size_of::<usize>())
                    .zip(addresses)
                    .map(|(chunk, address)| {
                        let value = usize::from_le_bytes(chunk.try_into().unwrap());
                        json!({ "address": format!("0x{address:X}"), "value": format!("0x{value:X}") })
                    })
                    .collect::<Vec<_>>();
                Ok(json!({ "stack_pointer": format!("0x{start:X}"), "values": values }))
            }
            "list_breakpoints" => {
                if !unsafe { (api.is_debugging)() } {
                    return Err("x64dbg has no active debuggee".to_owned());
                }
                let mut map = BpMap::default();
                let count = unsafe { (api.bp_list)(0, &mut map) };
                if map.bp.is_null() {
                    if count == 0 && map.count == 0 {
                        return Ok(json!({ "breakpoints": [] }));
                    }
                    return Err("x64dbg returned an invalid breakpoint list".to_owned());
                }
                let result = if !(0..=4096).contains(&count) || map.count != count {
                    Err("x64dbg returned an invalid or oversized breakpoint list".to_owned())
                } else {
                    let breakpoints = unsafe { std::slice::from_raw_parts(map.bp, count as usize) }
                        .iter()
                        .map(|bp| {
                            json!({
                                "address": format!("0x{:X}", bp.address),
                                "type": match bp.kind { 1 => "software", 2 => "hardware", 4 => "memory", 8 => "dll", 16 => "exception", _ => "unknown" },
                                "enabled": bp.enabled,
                                "active": bp.active,
                                "hits": bp.hit_count,
                                "name": c_text(&bp.name),
                                "module": c_text(&bp.module)
                            })
                        })
                        .collect::<Vec<_>>();
                    Ok(json!({ "breakpoints": breakpoints }))
                };
                unsafe { (api.bridge_free)(map.bp.cast()) };
                result
            }
            "set_breakpoint" | "remove_breakpoint" => {
                if !unsafe { (api.is_debugging)() } {
                    return Err("x64dbg has no active debuggee".to_owned());
                }
                let address = evaluate(api, text_param(params, "address", 256)?)?;
                let command = if method == "set_breakpoint" {
                    "bp"
                } else {
                    "bc"
                };
                let command = CString::new(format!("{command} 0x{address:X}")).unwrap();
                let success = unsafe { (api.command)(command.as_ptr()) };
                if !success {
                    return Err(format!("x64dbg could not {method} at 0x{address:X}"));
                }
                Ok(json!({ "success": success, "address": format!("0x{address:X}") }))
            }
            "write_memory" => {
                if !unsafe { (api.is_debugging)() } {
                    return Err("x64dbg has no active debuggee".to_owned());
                }
                let address = evaluate(api, text_param(params, "address", 256)?)?;
                let bytes = params
                    .get("bytes")
                    .and_then(Value::as_array)
                    .ok_or_else(|| "'bytes' must be an array of integers".to_owned())?;
                if !(1..=4096).contains(&bytes.len()) {
                    return Err("bytes must contain between 1 and 4096 values".to_owned());
                }
                let bytes = bytes
                    .iter()
                    .map(|value| {
                        value
                            .as_u64()
                            .filter(|&byte| byte <= u8::MAX as u64)
                            .map(|byte| byte as u8)
                            .ok_or_else(|| {
                                "each byte must be an integer from 0 through 255".to_owned()
                            })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if !unsafe { (api.mem_write)(address, bytes.as_ptr().cast(), bytes.len()) } {
                    return Err(format!("x64dbg could not write memory at 0x{address:X}"));
                }
                Ok(
                    json!({ "address": format!("0x{address:X}"), "length": bytes.len(), "success": true }),
                )
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

    #[cfg(test)]
    mod tests {
        use super::stack_addresses;

        #[test]
        fn stack_addresses_are_pointer_sized_and_bounded() {
            assert_eq!(
                stack_addresses(0x1000, 3).unwrap(),
                vec![
                    0x1000,
                    0x1000 + std::mem::size_of::<usize>(),
                    0x1000 + 2 * std::mem::size_of::<usize>()
                ]
            );
            assert!(stack_addresses(0, 0).is_err());
            assert!(stack_addresses(0, 65).is_err());
            assert!(stack_addresses(usize::MAX, 2).is_err());
        }

        #[test]
        fn breakpoint_layout_matches_x64dbg_bridge_abi() {
            let expected_size = if usize::BITS == 64 { 1824 } else { 1816 };
            assert_eq!(std::mem::size_of::<super::BridgeBp>(), expected_size);
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
        let expected_bp_size = if usize::BITS == 64 { 1824 } else { 1816 };
        if std::mem::size_of::<DisasmInstr>() != expected_size
            || std::mem::size_of::<BridgeBp>() != expected_bp_size
        {
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
