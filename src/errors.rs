#[derive(Debug)]
pub enum ProcMemError {
    CreateSnapshotFailure,
    IterateSnapshotFailure,
    ProcessNotFound,
    ModuleNotFound,
    GetHandleError,
    TerminateProcessError,
    ReadMemoryError,
    WriteMemoryError,
    SignatureNotFound,
    AddressOutOfBounds,
    RIPRelativeFailed,
}