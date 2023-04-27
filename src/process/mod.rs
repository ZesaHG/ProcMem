mod handle;
mod tlhelp32;
mod module;

use std::{process::Command, os::windows::process::CommandExt, mem::size_of};

use crate::ProcMemError;
use handle::Handle;
use tlhelp32::*;
pub use module::{Module, Signature};

use winapi::{um::{tlhelp32::{TH32CS_SNAPPROCESS, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32}, 
                  winbase::CREATE_NO_WINDOW, 
                  memoryapi::{ReadProcessMemory, WriteProcessMemory},
                  wow64apiset::IsWow64Process,
                 }, 
             shared::{minwindef::{FALSE, LPCVOID, LPVOID, BOOL, PBOOL}, basetsd::SIZE_T}
            };

#[derive(Debug)]

/// contains name, pid and handle of a process 
pub struct Process {
    pub process_name: String,
    /// unique identifier if the process
    pub process_id: u32,
    /// used when desired data is not inside a loaded module
    pub process_base_address: usize,
    /// either PROCESS_ALL_ACCESS or PROCESS_VM_READ | PROCESS_VM_WRITE
    pub process_handle: Handle,
}

impl Process {


    /// returns the desired process with the provided pid
    /// 
    /// ```rust
    /// use proc_mem::{Process, ProcMemError};
    /// let process: Result<Process,ProcMemError> = Process::with_pid(12345);
    /// ```
    pub fn with_pid(pid: u32) -> Result<Self,ProcMemError> {
        let h_snap = create_snapshot(TH32CS_SNAPPROCESS, 0)?;

        let mut pe32 = new_pe32w();

        if !process32first(&h_snap, &mut pe32) { return Err(ProcMemError::IterateSnapshotFailure);}

        loop {
            if pid.eq(&pe32.th32ProcessID) {
                let process_name = String::from_utf16_lossy(&pe32.szExeFile).trim_end_matches('\u{0}').to_string();

                let mut proc = Process {
                    process_name: String::from(&process_name), 
                    process_id: pid,
                    process_base_address: 0,
                    process_handle: Handle::read_write(pid)? 
                };
                
                proc.process_base_address = proc.module(&process_name)?.base_address();

                return Ok(proc)
            }

            if !process32next(&h_snap, &mut pe32) {break;}
        }
        Err(ProcMemError::ProcessNotFound)
    }


    /// returns the desired process with the provided name
    /// 
    /// ```rust
    /// use proc_mem::{Process, ProcMemError};
    /// let process: Result<Process,ProcMemError> = Process::with_name("process.exe");
    /// ```
    pub fn with_name(name: &str) -> Result<Self,ProcMemError> {
        let h_snap = create_snapshot(TH32CS_SNAPPROCESS, 0)?;

        let mut pe32 = new_pe32w();

        if !process32first(&h_snap, &mut pe32) { return Err(ProcMemError::IterateSnapshotFailure);}

        loop {
            let process_name = String::from_utf16_lossy(&pe32.szExeFile).trim_end_matches('\u{0}').to_string();
            if process_name.eq(&name) {

                let mut proc = Process {
                    process_name: String::from(&process_name), 
                    process_id: pe32.th32ProcessID,
                    process_base_address: 0,
                    process_handle: Handle::read_write(pe32.th32ProcessID)? 
                };
                
                proc.process_base_address = proc.module(&process_name)?.base_address();

                return Ok(proc)
            }

            if !process32next(&h_snap, &mut pe32) {break;}
        }
        Err(ProcMemError::ProcessNotFound)
    }


    /// returns a Vec<Process> where all processes share the provided name
    /// 
    /// ```rust
    /// use proc_mem::{Process, ProcMemError};
    /// let processes: Result<Vec<Process>,ProcMemError> = Process::all_with_name("process.exe");
    /// ```
    pub fn all_with_name(name: &str) -> Result<Vec<Process>,ProcMemError> {
        let mut results: Vec<Process> = Vec::new();

        let h_snap = create_snapshot(TH32CS_SNAPPROCESS, 0)?;

        let mut pe32 = new_pe32w();

        if !process32first(&h_snap, &mut pe32) { return Err(ProcMemError::IterateSnapshotFailure);}

        loop {
            let process_name = String::from_utf16_lossy(&pe32.szExeFile).trim_end_matches('\u{0}').to_string();
            if process_name.eq(&name) {

                let mut proc = Process {
                    process_name: String::from(&process_name), 
                    process_id: pe32.th32ProcessID,
                    process_base_address: 0,
                    process_handle: Handle::read_write(pe32.th32ProcessID)? 
                };

                proc.process_base_address = proc.module(&process_name)?.base_address();

                results.push(proc);
            }

            if !process32next(&h_snap, &mut pe32) {break;}
        }

        match results.is_empty() {
            true => return Err(ProcMemError::ProcessNotFound),
            false => return Ok(results)
        }
    }


    /// returns an instance of module including its base address in memory
    /// 
    /// ```rust
    /// use proc_mem::{Process, Module, ProcMemError};
    /// let process = Process::with_name("process.exe")?;
    /// let module: Result<Module,ProcMemError> = process.module("module.dll");
    /// ```
    pub fn module(&self, name: &str) -> Result<Module, ProcMemError> {
        let h_snap = create_snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, *self.pid())?;

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


    /// returns true if the process was terminated, otherwise will return false
    /// 
    /// ```rust
    /// use proc_mem::{Process};
    /// let process = Process::with_name("process.exe")?;
    /// let did_terminate: bool = process.kill();
    /// ```
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


    /// This function takes a type and the address to read.
    /// On success the read value will be returned.
    /// ```rust
    /// use proc_mem::{Process, Module, ProcMemError};
    /// let chrome = Process::with_name("chrome.exe")?;
    /// let module = chrome.module("kernel32.dll")?;
    /// let read_value: Result<T, ProcMemError> = chrome.read_mem::<T>(module.base_address() + 0x1337);
    /// ```
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


    /// This function takes a type and a Vec of addresses/offsets,
    /// the first entry being the base address to start from.
    /// On success the read value will be returned.
    /// ```rust
    /// use proc_mem::{Process, Module, ProcMemError};
    /// let chrome = Process::with_name("chrome.exe")?;
    /// let module = chrome.module("kernel32.dll")?;
    /// let chain: Vec<usize> = vec![module.base_address(), 0xDEA964, 0x100]
    /// let read_value: Result<T, ProcMemError> = chrome.read_mem_chain::<T>(chain);
    /// ```
    pub fn read_mem_chain<T: Default>(&self, mut chain: Vec<usize>) -> Result<T,ProcMemError> {
        let mut address = chain.remove(0);

        while chain.len() != 1 {
            address += chain.remove(0);
            address = if self.iswow64() {
                self.read_mem::<u32>(address)? as usize
            } else {
                self.read_mem::<u64>(address)? as usize
            }
        }

        let ret = self.read_mem::<T>(address + chain.remove(0))?;

        return Ok(ret);
    }


    /// This function takes a type and a Vec of addresses/offsets,
    /// the first entry being the base address to start from.
    /// On success the address at the end of the chain will be returned.
    /// ```rust
    /// use proc_mem::{Process, Module, ProcMemError};
    /// let some_game = Process::with_name("some_game.exe")?;
    /// let module = some_game.module("client.dll")?;
    /// let chain: Vec<usize> = vec![module.base_address(), 0xDEA964, 0x100]
    /// let desired_address: Result<usize, ProcMemError> = chrome.read_ptr_chain(chain);
    /// ```
    pub fn read_ptr_chain(&self, mut chain: Vec<usize>) -> Result<usize,ProcMemError> {
        let mut address = chain.remove(0);

        while chain.len() != 1 {
            address += chain.remove(0);
            address = if self.iswow64() {
                self.read_mem::<u32>(address)? as usize
            } else {
                self.read_mem::<u64>(address)? as usize
            }
        }

        return Ok(address + chain.remove(0));
    }


    /// This function takes a type and the address to write to.
    /// the returned boolean will be true on success and false on failure
    /// ```rust
    /// use proc_mem::{Process, Module};
    /// let chrome = Process::with_name("chrome.exe")?;
    /// let module = chrome.module("kernel32.dll")?;
    /// let write_result: bool = chrome.read_mem::<T>(module.base_address() + 0x1337);
    /// ```
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

    /// C style method to read memory
    /// ```rust
    /// use proc_mem::{Process, Module}
    /// let chrome = Process::with_name("chrome.exe")?;
    /// let module = chrome.module("kernel32.dll")?;
    /// let mut value_buffer: i32 = 0;
    /// if !chrome.read_ptr(value.buffer.as_mut_ptr(), module.base_address() + 0x1337) {
    ///     println!("ReadMemory Failure");
    /// } else {
    ///     println!("ReadMemory Success");
    /// }
    /// ```
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

    /// Returns a string slice of the process name
    pub fn name(&self) -> &str {
        &self.process_name
    }
    /// Returns the unique identifier aka. process id of the process
    pub fn pid(&self) -> &u32 {
        &self.process_id
    }
    // Determines whether the specified process is running under WOW64 or an Intel64 of x64 processor.
    pub fn iswow64(&self) -> bool {
        let mut tmp: BOOL = 0;
        unsafe {IsWow64Process(*self.process_handle, &mut tmp as PBOOL)};
        match tmp {
            FALSE => false,
            _ => true
        }
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