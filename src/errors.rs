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