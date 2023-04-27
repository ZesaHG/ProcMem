use regex::bytes::Regex;

use crate::ProcMemError;

/// contains info needed to find the byte pattern in memory
pub struct Signature {
    pub name: String,
    pub pattern: String,
    /// signature offsets for dereferencing
    pub offsets: Vec<isize>,
    /// added to the result
    pub extra: isize,
    /// get the address relative to the module
    pub relative: bool,
    /// read u32 at found address and add it to the result
    pub rip_relative: bool,
    /// added to the rip result
    pub rip_offset: isize,
}

/// contains info about the module and its content in bytes
#[derive(Debug)]
pub struct Module {
    module_name: String,
    module_path: String,
    process_id: u32,
    process_iswow64: bool,
    module_baseaddr: usize,
    module_basesize: usize,
    module_data: Vec<u8>
}

impl Module {
    pub fn new(mname: String, mpath: String, pid: u32, mbaseaddr: usize, mbasesize: usize, proc: &crate::Process) -> Self {
        Module { 
            module_name: mname,
            module_path: mpath, 
            process_id: pid,
            process_iswow64: proc.iswow64(), 
            module_baseaddr: mbaseaddr, 
            module_basesize: mbasesize,
            module_data: proc.read_module(mbaseaddr, mbasesize).unwrap_or_default(),
        }
    }

    pub fn name(&self) -> &str {&self.module_name}
    pub fn path(&self) -> &str {&self.module_path}
    pub fn pid(&self) -> &u32 {&self.process_id}
    pub fn base_address(&self) -> usize {self.module_baseaddr}
    pub fn base_size(&self) -> &usize {&self.module_basesize}
    pub fn data(&self) -> &Vec<u8>{&self.module_data}

    pub fn get_raw<T: Copy>(&self, mut o: usize, is_relative: bool) -> Option<T> {
        if !is_relative {
            o -= self.module_baseaddr;
        }
        if o + std::mem::size_of::<T>() >= self.module_data.len() {
            return None;
        }
        let ptr = self.module_data.get(o)?;
        let raw: T = unsafe { std::mem::transmute_copy(ptr) };
        Some(raw)
    }


    /// This functions finds an address in memory based on the provided [`Signature`]
    /// ```rust
    /// use proc_mem::{Process, Module, Signature, ProcMemError};
    /// let some_game: Result<Process,ProcMemError> = Process::with_name("some_game.exe");
    /// let module: Result<Module,ProcMemError> = some_game.module("module.dll");
    /// let lp_signature = Signature {
    ///     name: "LocalPlayer",
    ///     pattern: "8D 34 85 ? ? ? ? 89 15 ? ? ? ? 8B 41 08 8B 48 04 83 F9 FF",
    ///     offsets: vec![3],
    ///     extra: 4,
    ///     relative: true,
    ///     rip_relative: false,
    ///     rip_offset: 0,
    /// };
    /// let lp_address: Result<usize,ProcMemError> = module.find_signature(&lp_signature);
    /// ``` 
    pub fn find_signature(&self, sig: &Signature) -> Result<usize, ProcMemError> {
        let mut addr = Self::find_pattern(&self.module_data,&sig.pattern).ok_or(ProcMemError::SignatureNotFound)?;
        
        for (_i,o) in sig.offsets.iter().enumerate() {
            let pos = (addr as isize).wrapping_add(*o) as usize;
            let data = self.module_data.get(pos).ok_or_else(|| {
                ProcMemError::AddressOutOfBounds
            })?;
            let tmp = if self.process_iswow64 {
                let raw: u32 = unsafe {(data as *const u8).cast::<u32>().read_unaligned()};
                raw as usize
            } else {
                let raw: u64 = unsafe {(data as *const u8).cast::<u64>().read_unaligned()};
                raw as usize
            };

            addr = tmp.wrapping_sub(self.module_baseaddr);
        }

        if sig.rip_relative {
            addr = (addr as isize).wrapping_add(sig.rip_offset) as usize;
    
            let rip: u32 = self
                .get_raw(addr, true)
                .ok_or(ProcMemError::RIPRelativeFailed)?;

            addr = addr.wrapping_add(rip as usize + ::std::mem::size_of::<u32>());
        }
    
        addr = (addr as isize).wrapping_add(sig.extra) as usize;
        if !sig.relative {
            addr = addr.wrapping_add(self.module_baseaddr);
        }

        Ok(addr)
    }


    fn generate_regex(raw: &str) -> Option<Regex> {
        let mut res = raw
            .to_string()
            .split_whitespace()
            .map(|x| match &x {
                &"?" => ".".to_string(),
                x => format!("\\x{}", x),
            })
            .collect::<Vec<_>>()
            .join("");
        res.insert_str(0, "(?s-u)");
        Regex::new(&res).ok()
    }
    
    fn find_pattern(data: &[u8], pattern: &str) -> Option<usize> {
        Self::generate_regex(pattern)
            .and_then(|r| r.find(data))
            .and_then(|m| Some(m.start()))
    }
}