// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: Apache-2.0

//! A TPM Command Transmission Interface (TCTI) module, loadable by tpm2-tss's
//! dynamic TCTI loader (`tctildr`).
//!
//! The loader `dlopen`s this shared library, resolves the [`Tss2_Tcti_Info`]
//! symbol, and uses the returned [`info`](abi::TctiInfo) struct to instantiate
//! a context. From then on it drives the context through the C function
//! pointers (`transmit`, `receive`, `finalize`, ...) laid out at the start of
//! the context by the [TCTI ABI](abi).
//!
//! This module is the downstream half of `tpm2-proxyd`: it forwards the raw TPM
//! command byte stream to the proxy daemon over a Unix domain socket and reads
//! the raw response back. The TCTI config string is either a bare socket path
//! (`--tcti=proxy:/run/tpm2-proxyd/tpm2-proxyd.sock`) or comma-separated
//! `key=value` settings (`--tcti=proxy:path=/run/...sock,priority=5`):
//!
//! - `path`: the daemon's socket, default [`DEFAULT_SOCKET_PATH`].
//! - `priority`: the scheduling priority to request, a signed 32-bit integer
//!   where higher runs first. The default, `i32::MAX`, asks for the highest
//!   priority the daemon's policy allows this user.
//!
//! Wire protocol (must stay in sync with the daemon's `server::hello` and
//! `server::connection`): `init` sends a hello and checks the daemon's reply
//! (see [`hello`]). After that, each command is written verbatim and each
//! response is read back verbatim. TPM commands and responses are self-framing:
//! the 10-byte header carries the total size at bytes 2..6.

use std::ffi::{CStr, c_char, c_int, c_short, c_ulong, c_void};
use std::io::{ErrorKind, Read, Write};
use std::mem::ManuallyDrop;
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// C ABI definitions mirroring `tss2_tcti.h`. Layouts are `#[repr(C)]` so they
/// match the C structs the loader and ESYS expect byte-for-byte.
pub mod abi {
    use super::*;

    pub type Tss2Rc = u32;

    /// Opaque context pointer handed across the ABI (`TSS2_TCTI_CONTEXT *`).
    pub type TctiContext = c_void;

    pub type TransmitFn =
        unsafe extern "C" fn(ctx: *mut TctiContext, size: usize, command: *const u8) -> Tss2Rc;
    pub type ReceiveFn = unsafe extern "C" fn(
        ctx: *mut TctiContext,
        size: *mut usize,
        response: *mut u8,
        timeout: i32,
    ) -> Tss2Rc;
    pub type FinalizeFn = unsafe extern "C" fn(ctx: *mut TctiContext);
    pub type CancelFn = unsafe extern "C" fn(ctx: *mut TctiContext) -> Tss2Rc;
    pub type GetPollHandlesFn = unsafe extern "C" fn(
        ctx: *mut TctiContext,
        handles: *mut PollHandle,
        num_handles: *mut usize,
    ) -> Tss2Rc;
    pub type SetLocalityFn = unsafe extern "C" fn(ctx: *mut TctiContext, locality: u8) -> Tss2Rc;
    pub type MakeStickyFn =
        unsafe extern "C" fn(ctx: *mut TctiContext, handle: *mut u32, sticky: u8) -> Tss2Rc;
    pub type InitFn = unsafe extern "C" fn(
        ctx: *mut TctiContext,
        size: *mut usize,
        config: *const c_char,
    ) -> Tss2Rc;

    /// `TSS2_TCTI_POLL_HANDLE` is `struct pollfd` on Linux.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct PollHandle {
        pub fd: c_int,
        pub events: c_short,
        pub revents: c_short,
    }

    #[repr(C)]
    pub struct TctiContextCommonV1 {
        pub magic: u64,
        pub version: u32,
        pub transmit: TransmitFn,
        pub receive: ReceiveFn,
        pub finalize: FinalizeFn,
        pub cancel: CancelFn,
        pub get_poll_handles: GetPollHandlesFn,
        pub set_locality: SetLocalityFn,
    }

    #[repr(C)]
    pub struct TctiContextCommonV2 {
        pub v1: TctiContextCommonV1,
        pub make_sticky: MakeStickyFn,
    }

    #[repr(C)]
    pub struct TctiInfo {
        pub version: u32,
        pub name: *const c_char,
        pub description: *const c_char,
        pub config_help: *const c_char,
        pub init: InitFn,
    }

    // The info struct contains raw pointers (to 'static C strings); it is only
    // ever read, never mutated, so sharing it across threads is sound.
    unsafe impl Sync for TctiInfo {}

    pub const TSS2_RC_SUCCESS: Tss2Rc = 0;
    const TCTI_LAYER: Tss2Rc = 10 << 16;
    pub const TSS2_TCTI_RC_GENERAL_FAILURE: Tss2Rc = TCTI_LAYER | 1;
    pub const TSS2_TCTI_RC_NOT_IMPLEMENTED: Tss2Rc = TCTI_LAYER | 2;
    pub const TSS2_TCTI_RC_BAD_CONTEXT: Tss2Rc = TCTI_LAYER | 3;
    pub const TSS2_TCTI_RC_BAD_REFERENCE: Tss2Rc = TCTI_LAYER | 5;
    pub const TSS2_TCTI_RC_INSUFFICIENT_BUFFER: Tss2Rc = TCTI_LAYER | 6;
    pub const TSS2_TCTI_RC_BAD_SEQUENCE: Tss2Rc = TCTI_LAYER | 7;
    pub const TSS2_TCTI_RC_NO_CONNECTION: Tss2Rc = TCTI_LAYER | 8;
    pub const TSS2_TCTI_RC_TRY_AGAIN: Tss2Rc = TCTI_LAYER | 9;
    pub const TSS2_TCTI_RC_IO_ERROR: Tss2Rc = TCTI_LAYER | 10;
    pub const TSS2_TCTI_RC_BAD_VALUE: Tss2Rc = TCTI_LAYER | 11;
    pub const TSS2_TCTI_RC_MALFORMED_RESPONSE: Tss2Rc = TCTI_LAYER | 17;
    pub const TSS2_TCTI_RC_NOT_SUPPORTED: Tss2Rc = TCTI_LAYER | 21;

    /// TCTI ABI version implemented by this module (a V2 context).
    pub const TCTI_VERSION: u32 = 2;
}

use abi::*;

/// Magic identifying our context, "PRXYTCTI" interpreted as big-endian bytes.
const PROXY_MAGIC: u64 = 0x5052_5859_5443_5449;

/// Default daemon socket used when the TCTI config string is empty.
const DEFAULT_SOCKET_PATH: &str = "/run/tpm2-proxyd/tpm2-proxyd.sock";

/// Largest response the module accepts: the TPM's maximum response size.
const MAX_RESP_SIZE: usize = 4096;

const TPM_HEADER_SIZE: usize = 10;

/// Magic that opens the hello and its reply.
const HELLO_MAGIC: [u8; 4] = *b"TPXH";
/// Protocol version this module speaks.
const HELLO_VERSION: u16 = 1;
/// Size of the hello and of its reply.
const HELLO_SIZE: usize = 12;
/// How long to wait for the daemon's reply to the hello.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// Hello reply statuses.
const HELLO_ACCEPTED: u16 = 0;
const HELLO_UNSUPPORTED: u16 = 1;
const HELLO_BUSY: u16 = 2;

const STATE_TRANSMIT: u32 = 0;
const STATE_RECEIVE: u32 = 1;
const STATE_FINAL: u32 = 2;

/// Concrete context allocated by the caller and initialized in place by
/// [`tcti_proxy_init`]. The common ABI block must come first so the loader's
/// function-pointer offsets line up.
#[repr(C)]
struct ProxyContext {
    common: TctiContextCommonV2,
    state: u32,
    /// Connected Unix socket fd, or -1 once finalized.
    fd: RawFd,
    /// The response being received. It fills up across `receive` calls, so
    /// one that times out keeps what it read, and stays here until the caller
    /// takes it with a big enough buffer.
    response: [u8; MAX_RESP_SIZE],
    /// How many bytes of `response` have been read.
    received: usize,
}

impl ProxyContext {
    /// A context in the transmit state, connected to the daemon over `fd`.
    fn new(fd: RawFd) -> Self {
        Self {
            common: TctiContextCommonV2 {
                v1: TctiContextCommonV1 {
                    magic: PROXY_MAGIC,
                    version: TCTI_VERSION,
                    transmit: tcti_proxy_transmit,
                    receive: tcti_proxy_receive,
                    finalize: tcti_proxy_finalize,
                    cancel: tcti_proxy_cancel,
                    get_poll_handles: tcti_proxy_get_poll_handles,
                    set_locality: tcti_proxy_set_locality,
                },
                make_sticky: tcti_proxy_make_sticky,
            },
            state: STATE_TRANSMIT,
            fd,
            response: [0; MAX_RESP_SIZE],
            received: 0,
        }
    }

    /// Drop any partial response and go back to accepting commands.
    fn reset_receive(&mut self) {
        self.received = 0;
        self.state = STATE_TRANSMIT;
    }
}

const INFO_NAME: &CStr = c"proxy";
const INFO_DESCRIPTION: &CStr = c"TCTI module forwarding TPM commands to tpm2-proxyd.";
const INFO_CONFIG_HELP: &CStr =
    c"Path to the tpm2-proxyd Unix socket, or key=value pairs separated by commas: \
    path=<socket> (default /run/tpm2-proxyd/tpm2-proxyd.sock), \
    priority=<i32> (default: the highest the daemon's policy allows).";

static TCTI_INFO: TctiInfo = TctiInfo {
    version: TCTI_VERSION,
    name: INFO_NAME.as_ptr(),
    description: INFO_DESCRIPTION.as_ptr(),
    config_help: INFO_CONFIG_HELP.as_ptr(),
    init: tcti_proxy_init,
};

/// Entry point resolved by the TCTI loader (`TSS2_TCTI_INFO_SYMBOL`).
///
/// # Safety
/// Called by the C loader. Returns a pointer to a `'static` info struct.
#[unsafe(no_mangle)]
pub extern "C" fn Tss2_Tcti_Info() -> *const TctiInfo {
    &TCTI_INFO
}

/// Cast and validate an opaque context pointer to our [`ProxyContext`].
unsafe fn context_from_ptr<'a>(ctx: *mut TctiContext) -> Option<&'a mut ProxyContext> {
    if ctx.is_null() {
        return None;
    }
    let ctx = unsafe { &mut *(ctx as *mut ProxyContext) };
    if ctx.common.v1.magic != PROXY_MAGIC {
        return None;
    }
    Some(ctx)
}

/// Borrow a context's socket without taking ownership of the fd.
fn borrow_stream(fd: RawFd) -> ManuallyDrop<UnixStream> {
    ManuallyDrop::new(unsafe { UnixStream::from_raw_fd(fd) })
}

/// Two-phase init: with `ctx == NULL` it reports the required context size;
/// with a buffer it initializes the context in place and connects the socket.
///
/// # Safety
/// `ctx`/`size`/`config` come from the C loader and follow the TCTI init
/// contract.
unsafe extern "C" fn tcti_proxy_init(
    ctx: *mut TctiContext,
    size: *mut usize,
    config: *const c_char,
) -> Tss2Rc {
    // Size-query phase.
    if ctx.is_null() {
        if size.is_null() {
            return TSS2_TCTI_RC_BAD_VALUE;
        }
        unsafe { *size = size_of::<ProxyContext>() };
        return TSS2_RC_SUCCESS;
    }

    let config = if config.is_null() {
        Config::default()
    } else {
        match unsafe { CStr::from_ptr(config) }
            .to_str()
            .ok()
            .and_then(Config::parse)
        {
            Some(config) => config,
            None => return TSS2_TCTI_RC_BAD_VALUE,
        }
    };

    let mut stream = match UnixStream::connect(config.path) {
        Ok(s) => s,
        Err(_) => return TSS2_TCTI_RC_NO_CONNECTION,
    };
    if let Err(rc) = hello(&mut stream, config.priority) {
        return rc;
    }

    // Initialize the context in place; the buffer is owned by the caller.
    unsafe { (ctx as *mut ProxyContext).write(ProxyContext::new(stream.into_raw_fd())) };
    TSS2_RC_SUCCESS
}

/// Settings from the TCTI config string.
#[derive(Debug, PartialEq, Eq)]
struct Config<'a> {
    /// Daemon socket path.
    path: &'a str,
    /// Scheduling priority to request in the hello.
    priority: i32,
}

impl Default for Config<'_> {
    fn default() -> Self {
        Self {
            path: DEFAULT_SOCKET_PATH,
            priority: i32::MAX,
        }
    }
}

impl<'a> Config<'a> {
    /// Parse a config string: empty, a bare socket path, or comma-separated
    /// `path=`/`priority=` settings. Returns `None` if it's malformed.
    fn parse(config: &'a str) -> Option<Self> {
        let mut parsed = Self::default();
        if !config.contains('=') {
            if !config.is_empty() {
                parsed.path = config;
            }
            return Some(parsed);
        }
        for setting in config.split(',') {
            match setting.split_once('=')? {
                ("path", path) if !path.is_empty() => parsed.path = path,
                ("priority", priority) => parsed.priority = priority.parse().ok()?,
                _ => return None,
            }
        }
        Some(parsed)
    }
}

/// Send the hello requesting `priority`, and check the daemon's reply.
///
/// The hello is `"TPXH"`, a big-endian `u16` version, big-endian `u16` flags
/// (none are defined yet), and the big-endian `i32` requested priority. The
/// reply is `"TPXH"`, the daemon's version, a big-endian `u16` status, and the
/// big-endian `i32` priority the daemon granted. Nothing here needs the granted
/// priority, so it's not kept.
fn hello(stream: &mut UnixStream, priority: i32) -> Result<(), Tss2Rc> {
    let mut hello = [0u8; HELLO_SIZE];
    hello[..4].copy_from_slice(&HELLO_MAGIC);
    hello[4..6].copy_from_slice(&HELLO_VERSION.to_be_bytes());
    hello[8..].copy_from_slice(&priority.to_be_bytes());
    stream
        .set_read_timeout(Some(HELLO_TIMEOUT))
        .map_err(|_| TSS2_TCTI_RC_IO_ERROR)?;
    stream
        .write_all(&hello)
        .map_err(|_| TSS2_TCTI_RC_NO_CONNECTION)?;

    let mut reply = [0u8; HELLO_SIZE];
    stream
        .read_exact(&mut reply)
        .map_err(|_| TSS2_TCTI_RC_NO_CONNECTION)?;
    if reply[..4] != HELLO_MAGIC {
        return Err(TSS2_TCTI_RC_MALFORMED_RESPONSE);
    }
    match u16::from_be_bytes([reply[6], reply[7]]) {
        HELLO_ACCEPTED => Ok(()),
        HELLO_UNSUPPORTED => Err(TSS2_TCTI_RC_NOT_SUPPORTED),
        HELLO_BUSY => Err(TSS2_TCTI_RC_NO_CONNECTION),
        // A refusal this module doesn't know yet.
        _ => Err(TSS2_TCTI_RC_GENERAL_FAILURE),
    }
}

/// # Safety
/// Driven by the TCTI ABI: `command` points to `size` readable bytes.
unsafe extern "C" fn tcti_proxy_transmit(
    ctx: *mut TctiContext,
    size: usize,
    command: *const u8,
) -> Tss2Rc {
    let Some(ctx) = (unsafe { context_from_ptr(ctx) }) else {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    };
    if command.is_null() {
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }
    if ctx.state != STATE_TRANSMIT {
        return TSS2_TCTI_RC_BAD_SEQUENCE;
    }
    if size < TPM_HEADER_SIZE {
        return TSS2_TCTI_RC_BAD_VALUE;
    }

    let command = unsafe { std::slice::from_raw_parts(command, size) };
    // The daemon frames commands by the header's size field: one that
    // disagrees with `size` would leave it waiting for bytes that never come,
    // or read the rest as the start of the next command.
    if frame_size(command) != size {
        return TSS2_TCTI_RC_BAD_VALUE;
    }
    let mut stream = borrow_stream(ctx.fd);
    match stream.write_all(command).and_then(|()| stream.flush()) {
        Ok(()) => {
            ctx.state = STATE_RECEIVE;
            TSS2_RC_SUCCESS
        }
        Err(_) => TSS2_TCTI_RC_IO_ERROR,
    }
}

/// The total size in a TPM command or response header (bytes 2..6).
fn frame_size(frame: &[u8]) -> usize {
    match frame.get(2..6) {
        Some(&[a, b, c, d]) => u32::from_be_bytes([a, b, c, d]) as usize,
        _ => 0,
    }
}

/// # Safety
/// Driven by the TCTI ABI: `size` is the capacity of `response` on entry and
/// receives the actual response length on success. A NULL `response` asks
/// for the response's size. `timeout` is in milliseconds; negative
/// (`TSS2_TCTI_TIMEOUT_BLOCK`) waits indefinitely and 0
/// (`TSS2_TCTI_TIMEOUT_NONE`) doesn't wait at all. When it runs out the call
/// returns `TSS2_TCTI_RC_TRY_AGAIN`, keeping what it has read so far.
unsafe extern "C" fn tcti_proxy_receive(
    ctx: *mut TctiContext,
    size: *mut usize,
    response: *mut u8,
    timeout: i32,
) -> Tss2Rc {
    let Some(ctx) = (unsafe { context_from_ptr(ctx) }) else {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    };
    if size.is_null() {
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }
    if ctx.state != STATE_RECEIVE {
        return TSS2_TCTI_RC_BAD_SEQUENCE;
    }

    let total = match read_response(ctx, timeout) {
        Ok(total) => total,
        Err(rc) => return rc,
    };

    // Size query: report the exact size and keep the response for the next
    // call.
    if response.is_null() {
        unsafe { *size = total };
        return TSS2_RC_SUCCESS;
    }
    if unsafe { *size } < total {
        unsafe { *size = total };
        return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(ctx.response.as_ptr(), response, total);
        *size = total;
    }
    ctx.reset_receive();
    TSS2_RC_SUCCESS
}

/// Read the rest of the response into the context, waiting at most `timeout`
/// (as [`tcti_proxy_receive`] takes it) for more of it. Returns the
/// response's size once it's all in.
///
/// On an error other than `TSS2_TCTI_RC_TRY_AGAIN` the response is dropped
/// and the context goes back to the transmit state, as tcti-device does, so
/// the caller isn't left unable to send anything.
fn read_response(ctx: &mut ProxyContext, timeout: i32) -> Result<usize, Tss2Rc> {
    let deadline = u64::try_from(timeout)
        .ok()
        .map(|ms| Instant::now() + Duration::from_millis(ms));
    loop {
        // Read the header first, then as much as it says, never past the end
        // of this response.
        let wanted = if ctx.received < TPM_HEADER_SIZE {
            TPM_HEADER_SIZE
        } else {
            let total = frame_size(&ctx.response);
            if !(TPM_HEADER_SIZE..=MAX_RESP_SIZE).contains(&total) {
                ctx.reset_receive();
                return Err(TSS2_TCTI_RC_MALFORMED_RESPONSE);
            }
            if ctx.received >= total {
                return Ok(total);
            }
            total
        };

        match wait_readable(ctx.fd, deadline) {
            Ok(true) => {}
            Ok(false) => return Err(TSS2_TCTI_RC_TRY_AGAIN),
            Err(_) => {
                ctx.reset_receive();
                return Err(TSS2_TCTI_RC_IO_ERROR);
            }
        }
        // `received < wanted <= MAX_RESP_SIZE`: the header's size is checked above.
        let unread = &mut ctx.response[ctx.received..wanted];
        match borrow_stream(ctx.fd).read(unread) {
            Ok(0) => {
                ctx.reset_receive();
                return Err(TSS2_TCTI_RC_NO_CONNECTION);
            }
            Ok(n) => ctx.received += n,
            Err(e) if matches!(e.kind(), ErrorKind::Interrupted | ErrorKind::WouldBlock) => {}
            Err(_) => {
                ctx.reset_receive();
                return Err(TSS2_TCTI_RC_IO_ERROR);
            }
        }
    }
}

unsafe extern "C" {
    /// `poll(2)`; [`PollHandle`] is `struct pollfd` and `nfds_t` is an
    /// `unsigned long` on Linux.
    fn poll(fds: *mut PollHandle, nfds: c_ulong, timeout: c_int) -> c_int;
}

const POLLIN: c_short = 0x001;

/// Wait until `fd` is readable (or hung up), up to `deadline`: forever if
/// `None`. Returns whether it is.
fn wait_readable(fd: RawFd, deadline: Option<Instant>) -> std::io::Result<bool> {
    loop {
        let timeout = match deadline {
            None => -1,
            Some(deadline) => {
                let left = deadline.saturating_duration_since(Instant::now());
                // Round up so a sub-millisecond remainder still waits.
                c_int::try_from(left.as_nanos().div_ceil(1_000_000)).unwrap_or(c_int::MAX)
            }
        };
        let mut handle = PollHandle {
            fd,
            events: POLLIN,
            revents: 0,
        };
        match unsafe { poll(&mut handle, 1, timeout) } {
            0 => return Ok(false),
            n if n > 0 => return Ok(true),
            _ => {
                let e = std::io::Error::last_os_error();
                if e.kind() != ErrorKind::Interrupted {
                    return Err(e);
                }
            }
        }
    }
}

/// # Safety
/// Driven by the TCTI ABI; closes the socket and marks the context final.
unsafe extern "C" fn tcti_proxy_finalize(ctx: *mut TctiContext) {
    let Some(ctx) = (unsafe { context_from_ptr(ctx) }) else {
        return;
    };
    if ctx.fd >= 0 {
        // Reconstruct the stream so its Drop closes the fd.
        drop(unsafe { UnixStream::from_raw_fd(ctx.fd) });
        ctx.fd = -1;
    }
    ctx.state = STATE_FINAL;
}

/// # Safety
/// Driven by the TCTI ABI.
unsafe extern "C" fn tcti_proxy_cancel(_ctx: *mut TctiContext) -> Tss2Rc {
    // The daemon does not yet expose a cancel channel.
    TSS2_TCTI_RC_NOT_IMPLEMENTED
}

/// # Safety
/// Driven by the TCTI ABI: writes up to `*num_handles` entries into `handles`.
unsafe extern "C" fn tcti_proxy_get_poll_handles(
    ctx: *mut TctiContext,
    handles: *mut PollHandle,
    num_handles: *mut usize,
) -> Tss2Rc {
    let Some(ctx) = (unsafe { context_from_ptr(ctx) }) else {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    };
    if num_handles.is_null() {
        return TSS2_TCTI_RC_BAD_REFERENCE;
    }
    // First call (handles == NULL) reports how many handles we expose.
    if handles.is_null() {
        unsafe { *num_handles = 1 };
        return TSS2_RC_SUCCESS;
    }
    if unsafe { *num_handles } < 1 {
        return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
    }
    unsafe {
        *handles = PollHandle {
            fd: ctx.fd,
            events: POLLIN,
            revents: 0,
        };
        *num_handles = 1;
    }
    TSS2_RC_SUCCESS
}

/// # Safety
/// Driven by the TCTI ABI. The kernel resource manager has no notion of
/// locality to forward, so this only checks the call is in sequence.
unsafe extern "C" fn tcti_proxy_set_locality(ctx: *mut TctiContext, _locality: u8) -> Tss2Rc {
    let Some(ctx) = (unsafe { context_from_ptr(ctx) }) else {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    };
    if ctx.state != STATE_TRANSMIT {
        return TSS2_TCTI_RC_BAD_SEQUENCE;
    }
    TSS2_RC_SUCCESS
}

/// # Safety
/// Driven by the TCTI ABI.
unsafe extern "C" fn tcti_proxy_make_sticky(
    _ctx: *mut TctiContext,
    _handle: *mut u32,
    _sticky: u8,
) -> Tss2Rc {
    TSS2_TCTI_RC_NOT_IMPLEMENTED
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIMEOUT_BLOCK: i32 = -1;
    const TIMEOUT_NONE: i32 = 0;

    #[test]
    fn info_is_well_formed() {
        let info = unsafe { &*Tss2_Tcti_Info() };
        assert_eq!(info.version, TCTI_VERSION);
        let name = unsafe { CStr::from_ptr(info.name) };
        assert_eq!(name.to_str().unwrap(), "proxy");
        assert!(!info.description.is_null());
        assert!(!info.config_help.is_null());
    }

    #[test]
    fn init_size_query_reports_context_size() {
        let mut size = 0usize;
        let rc = unsafe { tcti_proxy_init(std::ptr::null_mut(), &mut size, std::ptr::null()) };
        assert_eq!(rc, TSS2_RC_SUCCESS);
        assert_eq!(size, size_of::<ProxyContext>());
    }

    #[test]
    fn init_size_query_without_size_is_bad_value() {
        let rc = unsafe {
            tcti_proxy_init(std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null())
        };
        assert_eq!(rc, TSS2_TCTI_RC_BAD_VALUE);
    }

    /// Run `init` against a fake daemon that answers the hello with `reply`,
    /// returning `init`'s result and the hello the daemon received. `settings`
    /// are appended to the config string's `path=` setting.
    fn init_against(settings: &str, reply: [u8; HELLO_SIZE]) -> (Tss2Rc, [u8; HELLO_SIZE]) {
        use std::os::unix::net::UnixListener;
        use std::sync::atomic::{AtomicU32, Ordering};

        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "tss2-tcti-proxy-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let daemon = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut hello = [0u8; HELLO_SIZE];
            stream.read_exact(&mut hello).unwrap();
            stream.write_all(&reply).unwrap();
            hello
        });

        let config =
            std::ffi::CString::new(format!("path={}{settings}", path.to_str().unwrap())).unwrap();
        let mut ctx = std::mem::MaybeUninit::<ProxyContext>::uninit();
        let mut size = size_of::<ProxyContext>();
        let ctx_ptr = ctx.as_mut_ptr().cast::<TctiContext>();
        let rc = unsafe { tcti_proxy_init(ctx_ptr, &mut size, config.as_ptr()) };
        if rc == TSS2_RC_SUCCESS {
            unsafe { tcti_proxy_finalize(ctx_ptr) };
        }
        let hello = daemon.join().unwrap();
        let _ = std::fs::remove_file(&path);
        (rc, hello)
    }

    #[test]
    fn init_maps_hello_refusals_to_tcti_errors() {
        let cases = [
            (
                "unsupported",
                *b"TPXH\0\x01\0\x01\0\0\0\0",
                TSS2_TCTI_RC_NOT_SUPPORTED,
            ),
            (
                "busy",
                *b"TPXH\0\x01\0\x02\0\0\0\0",
                TSS2_TCTI_RC_NO_CONNECTION,
            ),
            (
                "unknown status",
                *b"TPXH\0\x01\0\x09\0\0\0\0",
                TSS2_TCTI_RC_GENERAL_FAILURE,
            ),
            (
                "not a reply",
                *b"\x80\x01\0\0\0\x0c\0\0\x01\x7b\0\x08",
                TSS2_TCTI_RC_MALFORMED_RESPONSE,
            ),
        ];
        for (name, reply, expected) in cases {
            let (rc, hello) = init_against("", reply);
            assert_eq!(rc, expected, "{name}");
            assert_eq!(hello, *b"TPXH\0\x01\0\0\x7f\xff\xff\xff", "{name}");
        }
    }

    #[test]
    fn init_requests_the_configured_priority() {
        let (rc, hello) = init_against(",priority=-2", *b"TPXH\0\x01\0\0\xff\xff\xff\xfe");
        assert_eq!(rc, TSS2_RC_SUCCESS);
        assert_eq!(hello, *b"TPXH\0\x01\0\0\xff\xff\xff\xfe");
    }

    #[test]
    fn parses_config_strings() {
        let default = Config::default();
        let cases = [
            ("", Some(default)),
            (
                "/tmp/proxy.sock",
                Some(Config {
                    path: "/tmp/proxy.sock",
                    ..Config::default()
                }),
            ),
            (
                "priority=5",
                Some(Config {
                    priority: 5,
                    ..Config::default()
                }),
            ),
            (
                "path=/tmp/proxy.sock,priority=-3",
                Some(Config {
                    path: "/tmp/proxy.sock",
                    priority: -3,
                }),
            ),
            ("priority=high", None),
            ("priority=2147483648", None),
            ("path=", None),
            ("colour=blue", None),
            ("/tmp/proxy.sock,priority=5", None),
        ];
        for (config, expected) in cases {
            assert_eq!(Config::parse(config), expected, "{config:?}");
        }
    }

    /// A context connected to the peer end of a socket pair standing in for
    /// the daemon, as `init` leaves it after the hello.
    fn connected_context() -> (Box<ProxyContext>, UnixStream) {
        let (client, server) = UnixStream::pair().unwrap();
        (Box::new(ProxyContext::new(client.into_raw_fd())), server)
    }

    fn ptr(ctx: &mut ProxyContext) -> *mut TctiContext {
        (ctx as *mut ProxyContext).cast()
    }

    /// A 12-byte TPM2_GetRandom command (header size field = 12).
    const COMMAND: [u8; 12] = [0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x7b, 0x00, 0x08];
    /// A 14-byte response: 10-byte header plus 4 bytes of body.
    const RESPONSE: [u8; 14] = [0x80, 0x01, 0, 0, 0, 14, 0, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef];

    /// Transmit [`COMMAND`] and check the daemon got it verbatim.
    fn transmit_command(ctx: &mut ProxyContext, server: &mut UnixStream) {
        let rc = unsafe { tcti_proxy_transmit(ptr(ctx), COMMAND.len(), COMMAND.as_ptr()) };
        assert_eq!(rc, TSS2_RC_SUCCESS);
        let mut got = [0u8; COMMAND.len()];
        server.read_exact(&mut got).unwrap();
        assert_eq!(got, COMMAND);
    }

    fn receive(ctx: &mut ProxyContext, buf: &mut [u8], timeout: i32) -> (Tss2Rc, usize) {
        let mut size = buf.len();
        let rc = unsafe { tcti_proxy_receive(ptr(ctx), &mut size, buf.as_mut_ptr(), timeout) };
        (rc, size)
    }

    #[test]
    fn full_round_trip_over_socketpair() {
        let (mut ctx, mut server) = connected_context();
        transmit_command(&mut ctx, &mut server);
        server.write_all(&RESPONSE).unwrap();

        let mut buf = [0u8; 64];
        let (rc, size) = receive(&mut ctx, &mut buf, TIMEOUT_BLOCK);
        assert_eq!(rc, TSS2_RC_SUCCESS);
        assert_eq!(&buf[..size], &RESPONSE);

        unsafe { tcti_proxy_finalize(ptr(&mut ctx)) };
        assert_eq!(ctx.state, STATE_FINAL);
    }

    #[test]
    fn transmit_rejects_a_command_whose_header_size_disagrees() {
        let (mut ctx, mut server) = connected_context();
        let mut claims_more = COMMAND;
        claims_more[5] = 40;
        let mut claims_less = COMMAND;
        claims_less[5] = 10;
        for (name, command, size) in [
            ("claims more", &claims_more[..], claims_more.len()),
            ("claims less", &claims_less[..], claims_less.len()),
            ("shorter than a header", &COMMAND[..], 8),
        ] {
            let rc = unsafe { tcti_proxy_transmit(ptr(&mut ctx), size, command.as_ptr()) };
            assert_eq!(rc, TSS2_TCTI_RC_BAD_VALUE, "{name}");
        }
        // Nothing reached the daemon, and the context can still send.
        server.set_nonblocking(true).unwrap();
        let mut byte = [0u8; 1];
        assert_eq!(
            server.read(&mut byte).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        server.set_nonblocking(false).unwrap();
        transmit_command(&mut ctx, &mut server);
    }

    #[test]
    fn receive_without_a_timeout_does_not_wait() {
        let (mut ctx, mut server) = connected_context();
        transmit_command(&mut ctx, &mut server);
        // The daemon answers late; a no-wait receive must not wait for it.
        let late = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(500));
            server.write_all(&RESPONSE).unwrap();
            server
        });

        let mut buf = [0u8; 64];
        let (rc, _) = receive(&mut ctx, &mut buf, TIMEOUT_NONE);
        assert_eq!(rc, TSS2_TCTI_RC_TRY_AGAIN);

        let _server = late.join().unwrap();
        let (rc, size) = receive(&mut ctx, &mut buf, TIMEOUT_NONE);
        assert_eq!(rc, TSS2_RC_SUCCESS);
        assert_eq!(&buf[..size], &RESPONSE);
    }

    #[test]
    fn receive_keeps_what_it_read_when_the_timeout_fires() {
        let (mut ctx, mut server) = connected_context();
        transmit_command(&mut ctx, &mut server);
        server.write_all(&RESPONSE[..12]).unwrap();

        let mut buf = [0u8; 64];
        let start = std::time::Instant::now();
        let (rc, _) = receive(&mut ctx, &mut buf, 100);
        assert_eq!(rc, TSS2_TCTI_RC_TRY_AGAIN);
        assert!(start.elapsed() >= Duration::from_millis(100));

        server.write_all(&RESPONSE[12..]).unwrap();
        let (rc, size) = receive(&mut ctx, &mut buf, 100);
        assert_eq!(rc, TSS2_RC_SUCCESS);
        assert_eq!(&buf[..size], &RESPONSE);
    }

    #[test]
    fn receive_into_a_small_buffer_can_be_retried() {
        let (mut ctx, mut server) = connected_context();
        transmit_command(&mut ctx, &mut server);
        server.write_all(&RESPONSE).unwrap();
        // The response must already be buffered: the daemon has nothing more.
        drop(server);

        let mut size = 0;
        let rc = unsafe {
            tcti_proxy_receive(
                ptr(&mut ctx),
                &mut size,
                std::ptr::null_mut(),
                TIMEOUT_BLOCK,
            )
        };
        assert_eq!((rc, size), (TSS2_RC_SUCCESS, RESPONSE.len()));

        let mut small = [0u8; 12];
        let (rc, size) = receive(&mut ctx, &mut small, TIMEOUT_BLOCK);
        assert_eq!(
            (rc, size),
            (TSS2_TCTI_RC_INSUFFICIENT_BUFFER, RESPONSE.len())
        );

        let mut buf = [0u8; 64];
        let (rc, size) = receive(&mut ctx, &mut buf, TIMEOUT_BLOCK);
        assert_eq!(rc, TSS2_RC_SUCCESS);
        assert_eq!(&buf[..size], &RESPONSE);
        assert_eq!(ctx.state, STATE_TRANSMIT);
    }

    #[test]
    fn receive_reports_a_lost_daemon_and_resets() {
        let (mut ctx, mut server) = connected_context();
        transmit_command(&mut ctx, &mut server);
        server.write_all(&RESPONSE[..4]).unwrap();
        drop(server);

        let mut buf = [0u8; 64];
        let (rc, _) = receive(&mut ctx, &mut buf, TIMEOUT_BLOCK);
        assert_eq!(rc, TSS2_TCTI_RC_NO_CONNECTION);
        // Not stuck waiting for a response that will never come.
        assert_eq!(ctx.state, STATE_TRANSMIT);
    }

    #[test]
    fn receive_rejects_a_response_size_out_of_range() {
        for (name, size) in [("too small", 9u32), ("too large", 4097)] {
            let (mut ctx, mut server) = connected_context();
            transmit_command(&mut ctx, &mut server);
            let mut response = RESPONSE;
            response[2..6].copy_from_slice(&size.to_be_bytes());
            server.write_all(&response).unwrap();

            let mut buf = [0u8; 64];
            let (rc, _) = receive(&mut ctx, &mut buf, TIMEOUT_BLOCK);
            assert_eq!(rc, TSS2_TCTI_RC_MALFORMED_RESPONSE, "{name}");
            assert_eq!(ctx.state, STATE_TRANSMIT, "{name}");
        }
    }
}
