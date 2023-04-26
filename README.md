# ProcMem

Minimalistic rust library for dealing with processes, their modules and threads under Windows.
Furthermore ProcMem provides some functions to read/write to/from memory addresses within these processes/modules and to find memory adresses based on byte pattern.

## Installation

Use the package manager [cargo](https://doc.rust-lang.org/cargo/) to install ProcMem (cargo add proc_mem).
Or copy the newest version number from [crates.io](https://crates.io/crates/proc_mem)
and paste into your Cargo.toml file.

## Usage

### Example: get a running process

In order to get a running process you will have to
call [`Process::with_name()`] or [`Process::with_pid()`].
On success the returned value will be of type: [`Process`].

```rust
use proc_mem::Process;
let chrome:  Result<Process, ProcMemError> = Process::with_name("chrome.exe");
let firefox: Result<Process, ProcMemError> = Process::with_pid(12345);
```

### Example: terminate a process

```rust
use proc_mem::Process;
let chrome:  Result<Process, ProcMemError> = Process::with_name("chrome.exe");
let did_terminate: bool = chrome.kill();
```

### Example: get a module from a process

To get a module which was loaded by a process
you just have to call [`Process::module()`].
which on success will return an instance of [`Module`](crate::process::Module).

```rust
use proc_mem::{Process, Module};
let chrome = Process::with_name("chrome.exe")?;
let desired_module: Result<Module,ProcMemError> = chrome.module("kernel32.dll");
```

### Example: read/write memory

To read memory you have to call [`Process::read_mem()`].
This function takes a type and the address to read.
On success the read value will be returned.

```rust
use proc_mem::{Process, Module};
let chrome = Process::with_name("chrome.exe")?;
let module = chrome.module("kernel32.dll")?;
let read_value: Result<T, ProcMemError> = chrome.read_mem::<T>(module.base_address() + 0x1337);
```

To write memory you have to call [`Process::write_mem()`].
This function takes a type and the address to write to.
the returned boolean will be true on success and false on failure

```rust
use proc_mem::{Process, Module};
let chrome = Process::with_name("chrome.exe")?;
let module = chrome.module("kernel32.dll")?;
let write_result: bool = chrome.read_mem::<T>(module.base_address() + 0x1337);
```

There is also a function to read pointer chains [`Process::read_mem_chain()`].
This function takes a type and a Vec of addresses/offsets,
the first entry being the base address to start from.
On success the read value will be returned.

```rust
use proc_mem::{Process, Module};
let chrome = Process::with_name("chrome.exe")?;
let module = chrome.module("kernel32.dll")?;
let chain: Vec<usize> = vec![module.base_address(), 0xDEA964, 0x100]
let read_value: Result<T, ProcMemError> = chrome.read_mem_chain::<T>(chain);
```

### Example: pattern scanning

It´s a pain to maintain offsets manually, but luckily proc_mem
provides a way around that issue.
You can scan modules for byte patterns and get the desired address
this way.

```rust
use proc_mem::{Process, Module, Signature};
let some_game = Process::with_name("some_game.exe")?;
let module = some_game.module("module.dll")?;
let lp_signature = Signature {
    name: "LocalPlayer",
    pattern: "8D 34 85 ? ? ? ? 89 15 ? ? ? ? 8B 41 08 8B 48 04 83 F9 FF",
    offsets: vec![3],
    extra: 4,
    relative: true,
    rip_relative: false,
    rip_offset: 0,
};
let lp_address: Result<usize,ProcMemError> = module.find_signature(&lp_signature);
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests and documentations as appropriate.

## License

[MIT](https://choosealicense.com/licenses/mit/)
