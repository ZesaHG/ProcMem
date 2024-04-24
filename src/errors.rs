use std::error::Error;
use std::fmt::{self, Display, Formatter};

#[derive(Debug)]
pub enum ProcMemError {
    /// Could not take a snapshot of the processes/modules
    CreateSnapshotFailure,
    /// Could not iterate over the snapshot entries
    IterateSnapshotFailure,
    /// Process was not found in the snapshot of the processes
    ProcessNotFound,
    /// Module was not found in the snapshot of the modules
    ModuleNotFound,
    /// Could not get a HANDLE to read/write the process memory
    GetHandleError,
    /// Could not terminate the process
    TerminateProcessError,
    /// Could not read the process memory
    ReadMemoryError,
    /// Could not write to the process memory
    WriteMemoryError,
    /// Could not find the provided signature in the module
    SignatureNotFound,
    /// Signature pattern has lead out of bounds
    AddressOutOfBounds,
    /// Could not read the found address and add it to the result
    RIPRelativeFailed,
}

impl Display for ProcMemError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match &self {
                Self::CreateSnapshotFailure => "could not take a snapshot of the processes/modules",
                Self::IterateSnapshotFailure => "could not iterate over the snapshot entries",
                Self::ProcessNotFound => "process was not found in the snapshot of the processes",
                Self::ModuleNotFound => "module was not found in the snapshot of the modules",
                Self::GetHandleError => "could not get a HANDLE to read/write the process memory",
                Self::TerminateProcessError => "could not terminate the process",
                Self::ReadMemoryError => "could not read the process memory",
                Self::WriteMemoryError => "could not write to the process memory",
                Self::SignatureNotFound => "could not find the provided signature in the module",
                Self::AddressOutOfBounds => "signature pattern has lead out of bounds",
                Self::RIPRelativeFailed =>
                    "could not read the found address and add it to the result",
            }
        )
    }
}

impl Error for ProcMemError {}
