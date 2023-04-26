mod handle;
mod tlhelp32;
mod module;

use std::{process::Command, os::windows::process::CommandExt, mem::size_of};

use crate::ProcMemError;
use handle::Handle;
use tlhelp32::*;
pub use module::{Module, Signature};

use winapi::{um::{tlhelp32::{TH32CS_SNAPPROCESS, TH32CS_SNAPMODULE}, 
                  winbase::CREATE_NO_WINDOW, 
                  memoryapi::{ReadProcessMemory, WriteProcessMemory},
                 }, 
             shared::{minwindef::{FALSE, LPCVOID, LPVOID}, basetsd::SIZE_T}
            };

#[derive(Debug)]

/// contains name, pid of a process and a handle with
/// either PROCESS_ALL_ACCESS or PROCESS_VM_READ | PROCESS_VM_WRITE
pub struct Process {
    process_name: String,
    process_id: u32,
    process_handle: Handle,
}

impl Process {
    pub fn with_pid(pid: u32) -> Result<Self,ProcMemError> {
        let h_snap = create_snapshot(TH32CS_SNAPPROCESS, 0)?;

        let mut pe32 = new_pe32w();

        if !process32first(&h_snap, &mut pe32) { return Err(ProcMemError::IterateSnapshotFailure);}

        loop {
            if pid.eq(&pe32.th32ProcessID) {
                let process_name = String::from_utf16_lossy(&pe32.szExeFile).trim_end_matches('\u{0}').to_string();

                return Ok(Process { 
                    process_name, 
                    process_id: pid, 
                    process_handle: Handle::read_write(pid)? })
            }

            if !process32next(&h_snap, &mut pe32) {break;}
        }
        Err(ProcMemError::ProcessNotFound)
    }
    pub fn with_name(name: &str) -> Result<Self,ProcMemError> {
        let h_snap = create_snapshot(TH32CS_SNAPPROCESS, 0)?;

        let mut pe32 = new_pe32w();

        if !process32first(&h_snap, &mut pe32) { return Err(ProcMemError::IterateSnapshotFailure);}

        loop {
            let process_name = String::from_utf16_lossy(&pe32.szExeFile).trim_end_matches('\u{0}').to_string();
            if process_name.eq(&name) {
                return Ok(Process { 
                    process_name, 
                    process_id: pe32.th32ProcessID, 
                    process_handle: Handle::read_write(pe32.th32ProcessID)? })
            }

            if !process32next(&h_snap, &mut pe32) {break;}
        }
        Err(ProcMemError::ProcessNotFound)
    }
    /// returns an instance of module including its base address in memory
    pub fn module(&self, name: &str) -> Result<Module, ProcMemError> {
        let h_snap = create_snapshot(TH32CS_SNAPMODULE, *self.pid())?;

        let mut me32 = new_me32w();

        if !module32first(&h_snap, &mut me32) { return Err(ProcMemError::IterateSnapshotFailure);}
    
        loop {
            let module_name = String::from_utf16_lossy(&me32.szModule).trim_end_matches('\u{0}').to_string();
            if module_name.eq(name) {
                let module_path = String::from_utf16_lossy(&me32.szExePath).trim_end_matches('\u{0}').to_string();
                return Ok(Module::new(
                    module_name,
                    module_path,
                    *self.pid(),
                    me32.modBaseAddr as usize,
                    me32.modBaseSize as usize,
                    &self
                ))
            }

            if !module32next(&h_snap, &mut me32){break;}
        }
        Err(ProcMemError::ModuleNotFound)
    }

    pub fn kill(&self) -> bool {
        let output = Command::new("taskkill.exe")
        .arg("/PID")
        .arg(&self.process_id.to_string())
        .arg("/F")
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .expect("");

        if output.status.success() {
            println!("Process with PID {} was terminated", &self.process_id);
            true
        } else {
            println!(
                "Error killing process with PID {}: {}",
                &self.process_id,
                String::from_utf8_lossy(&output.stderr)
            );
            false
        }
    }

    pub fn read_mem<T: Default>(&self, address: usize) -> Result<T,ProcMemError> {
        let mut out:T = Default::default();

        unsafe {
            return if ReadProcessMemory(
                *self.process_handle, 
                address as *const _, 
                &mut out as *mut T as *mut _, 
                std::mem::size_of::<T>(), 
                0 as *mut _
            ) == FALSE {
                println!("ReadProcessMemory failed. Error: {:?}", std::io::Error::last_os_error());
                return Err(ProcMemError::ReadMemoryError);
            } else {Ok(out)};
        } 
    }
    pub fn read_mem_chain<T: Default>(&self, mut chain: Vec<usize>) -> Result<T,ProcMemError> {
        let mut address = chain.remove(0);

        while chain.len() != 1 {
            address += chain.remove(0);
            address = self.read_mem::<usize>(address)?;
        }

        let ret = self.read_mem::<T>(address + chain.remove(0))?;

        return Ok(ret);
    }
    pub fn write_mem<T: Default>(&self, address: usize, mut value: T) -> bool {
        unsafe {
            WriteProcessMemory(
                *self.process_handle, 
                address as *mut  _, 
                &mut value as *mut T as *mut _, 
                std::mem::size_of::<T>(), 
                0 as *mut usize
            ) != FALSE
        }
    }

    /// c style method to read memory
    pub fn read_ptr<T: Copy>(&self, buf: *mut T, address: usize, count: usize) -> bool {
        unsafe {
            ReadProcessMemory(
                *self.process_handle,
                address as LPCVOID,
                buf as *mut T as LPVOID,
                std::mem::size_of::<T>() as SIZE_T * count,
                std::ptr::null_mut::<SIZE_T>(),
            ) != FALSE
        }
    }

    pub fn name(&self) -> &str {
        &self.process_name
    }
    pub fn pid(&self) -> &u32 {
        &self.process_id
    }

    fn read_module(&self, address: usize, msize: usize) -> Result<Vec<u8>, ProcMemError> {
        let mut out = vec![0u8;msize];
        let out_ptr = out.as_mut_ptr();
        unsafe{
            if ReadProcessMemory(
                *self.process_handle, 
                address as LPCVOID, 
                out_ptr as LPVOID, 
                size_of::<u8>() as SIZE_T * msize, 
                std::ptr::null_mut::<SIZE_T>()
            ) == FALSE {
                Err(ProcMemError::ReadMemoryError)
            } else {
                Ok(out)
            }
        }    
    }
}