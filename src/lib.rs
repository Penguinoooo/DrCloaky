use windows::Win32::Foundation::{LRESULT, LPARAM, WPARAM};
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE,
};

#[unsafe(no_mangle)]
pub extern "system" fn HookProc(ncode: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let msg = unsafe { &*(lparam.0 as *const windows::Win32::UI::WindowsAndMessaging::MSG) };
    let hwnd = msg.hwnd;
    if !hwnd.is_invalid() {
        let _ = unsafe { SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) };
    }

    unsafe { CallNextHookEx(None, ncode, wparam, lparam) }
}
