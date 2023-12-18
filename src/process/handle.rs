use std::ops::Deref;

use winapi::um::{handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
                  winnt::{HANDLE, PROCESS_ALL_ACCESS, PROCESS_VM_READ, PROCESS_VM_WRITE}, 
                  processthreadsapi::OpenProcess
                 };

use crate::ProcMemError;


/// Wrapper around winapi HANDLE for automatic closing of the handle upon destruction


#[derive(Debug, Clone)]
pub struct Handle(pub HANDLE);

impl Deref for Handle {
    type Target = HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        if self.is_valid() {
            unsafe{CloseHandle(**self)};
        }
    }
}


impl Handle {
    /// if the wrapper contains a valid HANDLE this function returns true
    /// otherwise returns false
    pub fn is_valid(&self) -> bool {
        self.0 != INVALID_HANDLE_VALUE
    }
    /// when OpenProcess with PROCESS_ALL_ACCESS fails
    /// the function tries to OpenProcess with PROCESS_VM_READ & PROCESS_VM_WRITE
    /// if that fails too the function returns an ProcMemError
    pub fn read_write(pid: u32) -> Result<Self,ProcMemError> {
        let mut h = unsafe {OpenProcess(PROCESS_ALL_ACCESS, 0, pid)};
        if h == INVALID_HANDLE_VALUE {
            h = unsafe {OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE, 0, pid)};
            if h == INVALID_HANDLE_VALUE {Err(ProcMemError::GetHandleError)}
            else {Ok(Handle(h))}
        } else {Ok(Handle(h))}
    }
}