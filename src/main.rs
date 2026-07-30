#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_process_names() {
        assert_eq!(normalize_name("Slack.exe"), "slack");
        assert_eq!(normalize_name("  Teams  "), "teams");
    }

    #[test]
    fn parses_target_list() {
        let targets = parse_targets("Slack, Teams,Discord");
        assert_eq!(targets, vec!["slack", "teams", "discord"]);
    }

    #[test]
    fn matches_rules_by_executable_name() {
        let rule = Rule {
            id: "notepad".into(),
            executable: Some("notepad".into()),
            window_class: None,
            title: None,
            enabled: true,
        };

        assert!(matches_rule("notepad.exe", &rule));
        assert!(!matches_rule("teams.exe", &rule));
    }
}

use std::{
    env,
    ffi::CString,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use windows::core::{BOOL, PCSTR, PCWSTR, PWSTR};
use windows::Win32::Foundation::{HINSTANCE, HMODULE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowLongPtrW, GetWindowThreadProcessId, PostMessageW, SetWindowsHookExW,
    SetWindowLongPtrW, SetWindowPos, GWL_EXSTYLE, HWND_TOP, SWP_FRAMECHANGED, SWP_NOMOVE,
    SWP_NOZORDER, SWP_NOSIZE, WM_NULL, WH_GETMESSAGE, WS_EX_APPWINDOW,
};

const WS_EX_TOOLWINDOW_MASK: isize = 0x00000080;
const RULES_FILE: &str = "drcloaky_rules.json";

static HOOK_HANDLE: OnceLock<Mutex<Vec<usize>>> = OnceLock::new();

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Rule {
    id: String,
    executable: Option<String>,
    window_class: Option<String>,
    title: Option<String>,
    enabled: bool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct Config {
    enabled: bool,
    rules: Vec<Rule>,
}

#[derive(Debug, Clone)]
struct RuntimeState {
    config: Config,
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self {
            config: Config::default(),
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut config = load_config();

    if !args.is_empty() {
        config.rules = parse_targets(&args.join(","))
            .into_iter()
            .map(|executable| Rule {
                id: executable.clone(),
                executable: Some(executable),
                window_class: None,
                title: None,
                enabled: true,
            })
            .collect();
        config.enabled = true;
        save_config(&config);
    }

    if !config.enabled {
        config.enabled = true;
        save_config(&config);
    }

    let state = Arc::new(Mutex::new(RuntimeState { config }));
    println!("DrCloaky running in background mode.");
    println!("Rules file: {}", rules_file_path().display());

    let watcher_state = state.clone();
    thread::spawn(move || loop {
        let config = watcher_state.lock().unwrap().config.clone();
        if config.enabled {
            apply_cloak(&config.rules);
        }
        thread::sleep(Duration::from_secs(2));
    });

    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

fn normalize_name(name: &str) -> String {
    let cleaned = name.trim().to_lowercase();
    cleaned
        .trim_start_matches('\\')
        .trim_start_matches('/')
        .trim_end_matches(".exe")
        .to_string()
}

fn parse_targets(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(normalize_name)
        .collect()
}

fn apply_cloak(rules: &[Rule]) {
    let mut windows = Vec::new();

    unsafe {
        let _ = EnumWindows(Some(enum_windows_proc), LPARAM(&mut windows as *mut Vec<HWND> as isize));
    }

    for hwnd in windows {
        let Some(process_name) = window_process_name(hwnd) else {
            continue;
        };

        let matches = rules.iter().any(|rule| {
            rule.enabled
                && rule
                    .executable
                    .as_deref()
                    .map(|name| process_name.contains(name))
                    .unwrap_or(false)
        });

        if matches {
            let _ = install_hook_for_window(hwnd);
            let _ = set_taskbar_and_alt_tab_visibility(hwnd);
            println!("Applied cloak to {} ({:?})", process_name, hwnd.0);
        }
    }
}

unsafe extern "system" fn enum_windows_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let windows = lparam.0 as *mut Vec<HWND>;
    if !windows.is_null() {
        let windows = unsafe { &mut *windows };
        windows.push(hwnd);
    }
    BOOL(1)
}

fn matches_rule(process_name: &str, rule: &Rule) -> bool {
    rule.enabled
        && rule
            .executable
            .as_deref()
            .map(|name| process_name.contains(name))
            .unwrap_or(false)
}

fn install_hook_for_window(hwnd: HWND) -> bool {
    let mut pid = 0u32;
    let thread_id = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };

    if pid == 0 || thread_id == 0 {
        return false;
    }

    let dll_path = match std::env::current_exe() {
        Ok(exe_path) => exe_path
            .parent()
            .map(|dir| dir.join("drcloaky_hook.dll"))
            .unwrap_or_else(|| PathBuf::from("drcloaky_hook.dll")),
        Err(_) => PathBuf::from("drcloaky_hook.dll"),
    };

    let dll_path_str = dll_path.to_string_lossy().to_string();
    let dll_path_wide = dll_path_str.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let module = unsafe { LoadLibraryW(PCWSTR::from_raw(dll_path_wide.as_ptr())) };

    let Ok(module) = module else {
        return false;
    };

    if module == HMODULE(std::ptr::null_mut()) {
        return false;
    }

    let proc_name = CString::new("HookProc").unwrap();
    let proc_addr = unsafe { GetProcAddress(module, PCSTR::from_raw(proc_name.as_ptr() as *const u8)) };

    let Some(proc_addr) = proc_addr else {
        return false;
    };

    let hook_proc = unsafe { std::mem::transmute::<_, unsafe extern "system" fn(i32, WPARAM, LPARAM) -> LRESULT>(proc_addr) };
    let hook = unsafe { SetWindowsHookExW(WH_GETMESSAGE, Some(hook_proc), Some(HINSTANCE(module.0)), thread_id) };

    if let Ok(hook) = hook {
        let _ = unsafe { PostMessageW(Some(hwnd), WM_NULL, WPARAM(0), LPARAM(0)) };
        HOOK_HANDLE.get_or_init(|| Mutex::new(Vec::new())).lock().unwrap().push(hook.0 as usize);
        true
    } else {
        false
    }
}

fn set_taskbar_and_alt_tab_visibility(hwnd: HWND) -> bool {
    unsafe {
        let ex_style = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
        let mut new_style = ex_style;
        new_style &= !WS_EX_APPWINDOW.0 as isize;
        new_style |= WS_EX_TOOLWINDOW_MASK;
        let _ = SetWindowLongPtrW(hwnd, GWL_EXSTYLE, new_style);
        let _ = SetWindowPos(
            hwnd,
            Some(HWND_TOP),
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED,
        );
    }
    true
}

fn window_process_name(hwnd: HWND) -> Option<String> {
    let mut pid = 0u32;
    unsafe {
        let _ = GetWindowThreadProcessId(hwnd, Some(&mut pid));
    }

    if pid == 0 {
        return None;
    }

    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut buffer = [0u16; 260];
    let mut size = buffer.len() as u32;
    let _ = unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buffer.as_mut_ptr()),
            &mut size,
        )
    };

    let path = String::from_utf16_lossy(&buffer[..size as usize]);
    Some(Path::new(&path).file_name()?.to_string_lossy().to_lowercase())
}

fn rules_file_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(RULES_FILE)
}

fn load_config() -> Config {
    let path = rules_file_path();
    if !path.exists() {
        return Config::default();
    }

    match fs::read_to_string(&path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
        Err(_) => Config::default(),
    }
}

fn save_config(config: &Config) {
    let path = rules_file_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(path, serde_json::to_string_pretty(config).unwrap_or_default());
}

