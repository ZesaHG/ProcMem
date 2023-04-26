use std::mem::size_of;

use winapi::shared::minwindef::MAX_PATH;
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, PROCESSENTRY32W, LPPROCESSENTRY32W, Process32FirstW, Process32NextW, MODULEENTRY32W, MAX_MODULE_NAME32, LPMODULEENTRY32W, Module32FirstW, Module32NextW};

use crate::ProcMemError;
use crate::process::Handle;

/// Wrappers around tl32help functions to work a little cleaner

pub fn new_pe32w() -> PROCESSENTRY32W {
    PROCESSENTRY32W { 
        dwSize: size_of::<PROCESSENTRY32W>() as u32, 
        cntUsage: 0, 
        th32ProcessID: 0, 
        th32DefaultHeapID: 0, 
        th32ModuleID: 0, 
        cntThreads: 0, 
        th32ParentProcessID: 0, 
        pcPriClassBase: 0, 
        dwFlags: 0, 
        szExeFile: [0u16;260], 
    }
}
pub fn new_me32w() -> MODULEENTRY32W {
    MODULEENTRY32W { 
        dwSize: size_of::<MODULEENTRY32W>() as u32, 
        th32ModuleID: 0, 
        th32ProcessID: 0, 
        GlblcntUsage: 0, 
        ProccntUsage: 0, 
        modBaseAddr: std::ptr::null_mut(), 
        modBaseSize: 0, 
        hModule: std::ptr::null_mut(), 
        szModule: [0; MAX_MODULE_NAME32 + 1], 
        szExePath: [0; MAX_PATH] 
    }
}

pub fn create_snapshot(flags: u32, pid: u32) -> Result<Handle, ProcMemError> {
    let h_snap = Handle(unsafe{CreateToolhelp32Snapshot(flags, pid)});
    return if h_snap.is_valid() {
        Ok(h_snap)
    } else { Err(ProcMemError::CreateSnapshotFailure)};
}

pub fn process32first(h_snap: &Handle,pe32: LPPROCESSENTRY32W) -> bool {
    unsafe{Process32FirstW(**h_snap, pe32) != 0}
}
pub fn process32next(h_snap: &Handle,pe32: LPPROCESSENTRY32W) -> bool {
    unsafe{Process32NextW(**h_snap, pe32) != 0}
}

pub fn module32first(h_snap: &Handle,me32: LPMODULEENTRY32W) -> bool {
    unsafe{Module32FirstW(**h_snap, me32) != 0}
}
pub fn module32next(h_snap: &Handle,me32: LPMODULEENTRY32W) -> bool {
    unsafe{Module32NextW(**h_snap, me32) != 0}
}