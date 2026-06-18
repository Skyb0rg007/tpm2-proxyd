// SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
//
// SPDX-License-Identifier: BSD-2-Clause
//! Rust interfaces to systemd protocols.
//!
//! This module exposes systemd socket activation helpers
//! and systemd notifications.

#![allow(dead_code)]

// If this service ends up needing large caches, consider implementing
// the Memory Pressure API (https://systemd.io/MEMORY_PRESSURE/).
// This service doesn't need to reload configuration, but if it did consider
// implementing sd_pid_notify_with_fds to use the FDSTORE.
use rustix::fd::{FromRawFd, OwnedFd};
use rustix::fs;
use rustix::io;
use rustix::net;
use rustix::process::{PidfdFlags, RawPid, getpid, pidfd_open};
use std::env;
use std::num::NonZeroU64;
use std::os::unix::ffi::OsStrExt;

const SD_LISTEN_FDS_START: i32 = 3;

const LISTEN_FDNAMES: &str = "LISTEN_FDNAMES";
const LISTEN_FDS: &str = "LISTEN_FDS";
const LISTEN_PIDFDID: &str = "LISTEN_PIDFDID";
const LISTEN_PID: &str = "LISTEN_PID";
const NOTIFY_SOCKET: &str = "NOTIFY_SOCKET";
const WATCHDOG_PID: &str = "WATCHDOG_PID";
const WATCHDOG_USEC: &str = "WATCHDOG_USEC";

const PID_FS_MAGIC: i32 = i32::from_be_bytes(*b"PIDF");

/// Returns the passed file descriptors as `OwnedFd`s,
/// so they will be closed when dropped.
pub fn sd_listen_fds() -> io::Result<Vec<OwnedFd>> {
    let listen_pid = env::var_os(LISTEN_PID)
        .ok_or(io::Errno::INVAL)?
        .to_str()
        .ok_or(io::Errno::INVAL)?
        .parse::<RawPid>()
        .map_err(|_| io::Errno::INVAL)?;
    if listen_pid != getpid().as_raw_pid() {
        return Ok(Vec::new());
    }

    match env::var(LISTEN_PIDFDID) {
        Err(env::VarError::NotPresent) => (),
        Err(env::VarError::NotUnicode(_)) => return Err(io::Errno::INVAL),
        Ok(listen_pidfdid) => {
            let pidfdid = listen_pidfdid
                .parse::<u64>()
                .map_err(|_| io::Errno::INVAL)?;

            // An I/O error isn't fatal since the pidfdid check is optional
            if let Ok(own_pidfdid) = getpidfdid()
                && own_pidfdid != pidfdid
            {
                return Ok(Vec::new());
            }
        }
    }

    let listen_fds = env::var_os(LISTEN_FDS)
        .ok_or(io::Errno::INVAL)?
        .to_str()
        .ok_or(io::Errno::INVAL)?
        .parse::<i32>()
        .map_err(|_| io::Errno::INVAL)?;
    if listen_fds > i32::MAX - SD_LISTEN_FDS_START {
        return Err(io::Errno::INVAL);
    }

    let mut owned_fds = Vec::with_capacity(listen_fds as usize);

    for n in SD_LISTEN_FDS_START..SD_LISTEN_FDS_START + listen_fds {
        let fd = unsafe { OwnedFd::from_raw_fd(n) };

        // Mark all of the file descriptors as close-on-exec
        let flags = io::fcntl_getfd(&fd)?;
        let nflags = flags | io::FdFlags::CLOEXEC;
        if flags != nflags {
            io::fcntl_setfd(&fd, nflags)?;
        }

        owned_fds.push(fd);
    }

    Ok(owned_fds)
}

/// Same as sd_listen_fds, but also returns their names
pub fn sd_listen_fds_with_names() -> io::Result<(Option<Vec<String>>, Vec<OwnedFd>)> {
    let fds = sd_listen_fds()?;

    let listen_fdnames = match env::var(LISTEN_FDNAMES) {
        Ok(e) => e,
        Err(env::VarError::NotPresent) => return Ok((None, fds)),
        Err(env::VarError::NotUnicode(_)) => return Err(io::Errno::INVAL),
    };

    let names: Vec<String> = listen_fdnames.split(':').map(|s| s.into()).collect();

    if names.len() != fds.len() {
        return Err(io::Errno::INVAL);
    }

    Ok((Some(names), fds))
}

/// Unsets systemd socket activation environment variables
/// This function is only safe to call in a single-threaded program
pub unsafe fn sd_listen_unsetenv() {
    unsafe {
        env::remove_var(LISTEN_FDNAMES);
        env::remove_var(LISTEN_FDS);
        env::remove_var(LISTEN_PID);
        env::remove_var(LISTEN_PIDFDID);
    }
}

/// Determine if the service is running under a systemd watchdog
/// If so, returns the number of microseconds allowed between notifications.
pub fn sd_watchdog_enabled() -> io::Result<Option<NonZeroU64>> {
    let Some(watchdog_usec) = env::var_os(WATCHDOG_USEC) else {
        return Ok(None);
    };
    let usec = watchdog_usec
        .to_str()
        .ok_or(io::Errno::INVAL)?
        .parse::<u64>()
        .map_err(|_| io::Errno::INVAL)?;
    if usec == u64::MAX {
        return Err(io::Errno::INVAL);
    }
    let usec = NonZeroU64::new(usec).ok_or(io::Errno::INVAL)?;

    if let Some(watchdog_pid) = env::var_os(WATCHDOG_PID) {
        let pid = watchdog_pid
            .to_str()
            .ok_or(io::Errno::INVAL)?
            .parse::<RawPid>()
            .map_err(|_| io::Errno::INVAL)?;
        if pid != getpid().as_raw_pid() {
            return Ok(None);
        }
    };

    Ok(Some(usec))
}

/// Unsets systemd watchdog environment variables
/// This function is only safe to call in a single-threaded program
pub unsafe fn sd_watchdog_unsetenv() {
    unsafe {
        env::remove_var(WATCHDOG_PID);
        env::remove_var(WATCHDOG_USEC);
    }
}

/// Perform a systemd notification
/// Returns false if $NOTIFY_SOCKET is not set.
pub fn sd_notify(message: &str) -> io::Result<bool> {
    let Some(socket_path) = env::var_os(NOTIFY_SOCKET) else {
        return Ok(false);
    };

    let path = socket_path.as_bytes();
    let addr = if let Some(name) = path.strip_prefix(b"@") {
        net::SocketAddrUnix::new_abstract_name(name)?
    } else {
        net::SocketAddrUnix::new(socket_path.as_os_str())?
    };
    let sock = net::socket_with(
        net::AddressFamily::UNIX,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        /* protocol= */ None,
    )?;
    net::connect(&sock, &addr)?;

    let written = io::write(&sock, message.as_bytes())?;
    if written != message.len() {
        return Err(io::Errno::PROTO);
    }

    Ok(true)
}

/// Get the 64-bit inode of the current process's pidfd
fn getpidfdid() -> io::Result<u64> {
    if size_of::<rustix::ffi::c_ulong>() < 8 {
        return Err(io::Errno::OPNOTSUPP);
    }

    let pid = getpid();
    let pidfd = pidfd_open(pid, PidfdFlags::empty())?;
    let fsstat = fs::fstatfs(&pidfd)?;
    if fsstat.f_type != PID_FS_MAGIC as fs::FsWord {
        return Err(io::Errno::OPNOTSUPP);
    }

    // XXX: use name_to_handle_at once added to rustix
    // Once that happens we can support 32-bit Linux

    let stat = fs::fstat(&pidfd)?;
    Ok(stat.st_ino as u64)
}
