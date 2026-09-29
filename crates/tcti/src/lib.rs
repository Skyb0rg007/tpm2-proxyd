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
//! the raw response back. The socket path is taken from the TCTI config string
//! (e.g. `--tcti=proxy:/run/tpm2-proxyd/tpm2-proxyd.sock`), defaulting to
//! [`DEFAULT_SOCKET_PATH`].
//!
//! Wire protocol (must stay in sync with the daemon's `server::hello` and
//! `server::connection`): `init` sends a hello and checks the daemon's reply
//! (see [`hello`]). After that, each command is written verbatim and each
//! response is read back verbatim. TPM commands and responses are self-framing:
//! the 10-byte header carries the total size at bytes 2..6.

use std::ffi::{CStr, c_char, c_int, c_short, c_void};
use std::io::{Read, Write};
use std::mem::ManuallyDrop;
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

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

/// Largest response we are willing to report for a size-query receive call.
const MAX_RESP_SIZE: usize = 4096;

const TPM_HEADER_SIZE: usize = 10;

/// Magic that opens the hello and its reply.
const HELLO_MAGIC: [u8; 4] = *b"TPXH";
/// Protocol version this module speaks.
const HELLO_VERSION: u16 = 1;
/// Size of the hello and of its reply.
const HELLO_SIZE: usize = 8;
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
    locality: u8,
    /// Connected Unix socket fd, or -1 once finalized.
    fd: RawFd,
}

const INFO_NAME: &CStr = c"proxy";
const INFO_DESCRIPTION: &CStr = c"TCTI module forwarding TPM commands to tpm2-proxyd.";
const INFO_CONFIG_HELP: &CStr =
    c"Path to the tpm2-proxyd Unix socket. Default: /run/tpm2-proxyd/tpm2-proxyd.sock";

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

/// Borrow the context's socket without taking ownership of the fd.
fn borrow_stream(ctx: &ProxyContext) -> ManuallyDrop<UnixStream> {
    ManuallyDrop::new(unsafe { UnixStream::from_raw_fd(ctx.fd) })
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

    let path = if config.is_null() {
        DEFAULT_SOCKET_PATH
    } else {
        match unsafe { CStr::from_ptr(config) }.to_str() {
            Ok(s) if !s.is_empty() => s,
            Ok(_) => DEFAULT_SOCKET_PATH,
            Err(_) => return TSS2_TCTI_RC_BAD_VALUE,
        }
    };

    let mut stream = match UnixStream::connect(path) {
        Ok(s) => s,
        Err(_) => return TSS2_TCTI_RC_NO_CONNECTION,
    };
    if let Err(rc) = hello(&mut stream) {
        return rc;
    }

    // Initialize the context in place; the buffer is owned by the caller.
    let slot = ctx as *mut ProxyContext;
    unsafe {
        slot.write(ProxyContext {
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
            locality: 0,
            fd: stream.into_raw_fd(),
        });
    }
    TSS2_RC_SUCCESS
}

/// Send the hello and check the daemon's reply.
///
/// The hello is `"TPXH"`, a big-endian `u16` version, and big-endian `u16`
/// flags (none are defined yet). The reply is `"TPXH"`, the daemon's version,
/// and a big-endian `u16` status.
fn hello(stream: &mut UnixStream) -> Result<(), Tss2Rc> {
    let mut hello = [0u8; HELLO_SIZE];
    hello[..4].copy_from_slice(&HELLO_MAGIC);
    hello[4..6].copy_from_slice(&HELLO_VERSION.to_be_bytes());
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
    let mut stream = borrow_stream(ctx);
    match stream.write_all(command).and_then(|()| stream.flush()) {
        Ok(()) => {
            ctx.state = STATE_RECEIVE;
            TSS2_RC_SUCCESS
        }
        Err(_) => TSS2_TCTI_RC_IO_ERROR,
    }
}

/// # Safety
/// Driven by the TCTI ABI: `size` is the capacity of `response` on entry and
/// receives the actual response length on success.
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

    // Size-query call: report an upper bound without consuming the response.
    if response.is_null() {
        unsafe { *size = MAX_RESP_SIZE };
        return TSS2_RC_SUCCESS;
    }

    let mut stream = borrow_stream(ctx);
    let read_timeout = (timeout > 0).then(|| Duration::from_millis(timeout as u64));
    if stream.set_read_timeout(read_timeout).is_err() {
        return TSS2_TCTI_RC_IO_ERROR;
    }

    // Read the 10-byte header to learn the full response size.
    let mut header = [0u8; TPM_HEADER_SIZE];
    if let Err(e) = stream.read_exact(&mut header) {
        return io_err_to_rc(e);
    }
    let total = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
    if total < TPM_HEADER_SIZE {
        return TSS2_TCTI_RC_MALFORMED_RESPONSE;
    }

    let capacity = unsafe { *size };
    if capacity < total {
        // Caller must retry with a larger buffer; the header is already
        // consumed, so this connection cannot continue afterwards.
        unsafe { *size = total };
        return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
    }

    let out = unsafe { std::slice::from_raw_parts_mut(response, total) };
    out[..TPM_HEADER_SIZE].copy_from_slice(&header);
    if let Err(e) = stream.read_exact(&mut out[TPM_HEADER_SIZE..total]) {
        return io_err_to_rc(e);
    }

    unsafe { *size = total };
    ctx.state = STATE_TRANSMIT;
    TSS2_RC_SUCCESS
}

fn io_err_to_rc(e: std::io::Error) -> Tss2Rc {
    use std::io::ErrorKind::*;
    match e.kind() {
        WouldBlock | TimedOut => TSS2_TCTI_RC_TRY_AGAIN,
        _ => TSS2_TCTI_RC_IO_ERROR,
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
    const POLLIN: c_short = 0x001;
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
/// Driven by the TCTI ABI.
unsafe extern "C" fn tcti_proxy_set_locality(ctx: *mut TctiContext, locality: u8) -> Tss2Rc {
    let Some(ctx) = (unsafe { context_from_ptr(ctx) }) else {
        return TSS2_TCTI_RC_BAD_CONTEXT;
    };
    if ctx.state != STATE_TRANSMIT {
        return TSS2_TCTI_RC_BAD_SEQUENCE;
    }
    ctx.locality = locality;
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
    /// returning `init`'s result and the hello the daemon received.
    fn init_against(reply: [u8; HELLO_SIZE]) -> (Tss2Rc, [u8; HELLO_SIZE]) {
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

        let config = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
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
                *b"TPXH\0\x01\0\x01",
                TSS2_TCTI_RC_NOT_SUPPORTED,
            ),
            ("busy", *b"TPXH\0\x01\0\x02", TSS2_TCTI_RC_NO_CONNECTION),
            (
                "unknown status",
                *b"TPXH\0\x01\0\x09",
                TSS2_TCTI_RC_GENERAL_FAILURE,
            ),
            (
                "not a reply",
                *b"\x80\x01\0\0\0\x0a\0\0",
                TSS2_TCTI_RC_MALFORMED_RESPONSE,
            ),
        ];
        for (name, reply, expected) in cases {
            let (rc, hello) = init_against(reply);
            assert_eq!(rc, expected, "{name}");
            assert_eq!(hello, *b"TPXH\0\x01\0\0", "{name}");
        }
    }

    #[test]
    fn full_round_trip_over_socketpair() {
        // Stand in for the daemon with the peer end of a socket pair.
        let (client, mut server) = UnixStream::pair().unwrap();

        let mut ctx = ProxyContext {
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
            locality: 0,
            fd: client.into_raw_fd(),
        };
        let ctx_ptr = (&mut ctx as *mut ProxyContext).cast::<TctiContext>();

        // A 12-byte TPM2_GetRandom-shaped command (header size field = 12).
        let cmd = [0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x7b, 0x00, 0x08];
        let rc = unsafe { tcti_proxy_transmit(ctx_ptr, cmd.len(), cmd.as_ptr()) };
        assert_eq!(rc, TSS2_RC_SUCCESS);

        let mut got = [0u8; 12];
        server.read_exact(&mut got).unwrap();
        assert_eq!(got, cmd);

        // Server replies with a 14-byte response (10 header + 4 body).
        let resp = [
            0x80u8, 0x01, 0, 0, 0, 14, 0, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef,
        ];
        server.write_all(&resp).unwrap();

        let mut buf = [0u8; 64];
        let mut size = buf.len();
        let rc = unsafe { tcti_proxy_receive(ctx_ptr, &mut size, buf.as_mut_ptr(), -1) };
        assert_eq!(rc, TSS2_RC_SUCCESS);
        assert_eq!(size, resp.len());
        assert_eq!(&buf[..size], &resp);

        unsafe { tcti_proxy_finalize(ctx_ptr) };
        assert_eq!(ctx.state, STATE_FINAL);
    }
}
