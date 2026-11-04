// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use std::fs::File;
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, GENERIC_READ,
    GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OVERLAPPED, ReadFile, WriteFile};
use windows_sys::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Threading::CreateEventW;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
    SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    WaitNamedPipeW,
};

use super::{Connection, Connector, Duplex, Listener};

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: this wrapper owns the handle.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// Run one overlapped operation on `handle` and wait for it. Each
/// operation has its own event, so a read pending on one clone of a
/// handle does not hold up a write on another: synchronous handles on
/// one file object are serialized, overlapped ones are not.
fn overlapped(handle: HANDLE, start: impl FnOnce(*mut OVERLAPPED) -> i32) -> std::io::Result<u32> {
    // SAFETY: an unnamed manual-reset event, closed by `Owned`.
    let event = Owned(unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) });
    if event.0.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: an all-zero OVERLAPPED is its documented initial state.
    let mut operation: OVERLAPPED = unsafe { std::mem::zeroed() };
    operation.hEvent = event.0;
    if start(&mut operation) == 0 {
        // SAFETY: reads this thread's last error.
        let error = unsafe { GetLastError() };
        if error != ERROR_IO_PENDING {
            return Err(std::io::Error::from_raw_os_error(error as i32));
        }
    }
    let mut done = 0u32;
    // SAFETY: `operation` outlives the wait, which blocks until it completes.
    if unsafe { GetOverlappedResult(handle, &operation, &mut done, 1) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(done)
}

/// A connected pipe end, opened for overlapped I/O.
struct PipeStream {
    file: File,
    server: bool,
}

impl std::io::Read for PipeStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let handle = self.file.as_raw_handle() as HANDLE;
        let len = buf.len().min(u32::MAX as usize) as u32;
        // SAFETY: `buf` is valid for `len` bytes until the operation completes.
        match overlapped(handle, |op| unsafe { ReadFile(handle, buf.as_mut_ptr(), len, std::ptr::null_mut(), op) }) {
            Ok(read) => Ok(read as usize),
            // A closed pipe is the end of the stream.
            Err(error) if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) => Ok(0),
            Err(error) => Err(error),
        }
    }
}

impl std::io::Write for PipeStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let handle = self.file.as_raw_handle() as HANDLE;
        let len = buf.len().min(u32::MAX as usize) as u32;
        // SAFETY: `buf` is valid for `len` bytes until the operation completes.
        overlapped(handle, |op| unsafe { WriteFile(handle, buf.as_ptr(), len, std::ptr::null_mut(), op) }).map(|n| n as usize)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Duplex for PipeStream {
    fn try_clone_duplex(&self) -> std::io::Result<Box<dyn Duplex>> {
        Ok(Box::new(PipeStream {
            file: self.file.try_clone()?,
            server: self.server,
        }))
    }

    fn shutdown_both(&self) {
        let handle = self.file.as_raw_handle() as HANDLE;
        // SAFETY: the handle is live for this stream's lifetime.
        unsafe {
            windows_sys::Win32::System::IO::CancelIoEx(handle, std::ptr::null());
            if self.server {
                DisconnectNamedPipe(handle);
            }
        }
    }
}

/// The protected DACL every custodian pipe carries: full control for
/// SYSTEM and the creator (the service), read and write for the owner,
/// nothing inherited.
pub fn owner_pipe_sddl(owner_sid: &str) -> String {
    format!("D:P(A;;GA;;;SY)(A;;GA;;;OW)(A;;GRGW;;;{owner_sid})")
}

/// A security descriptor from SDDL, for a pipe created here or by the
/// SSH agent's listener.
pub struct PipeSecurity(*mut core::ffi::c_void);

// SAFETY: the descriptor is immutable once converted and freed once.
unsafe impl Send for PipeSecurity {}
unsafe impl Sync for PipeSecurity {}

impl PipeSecurity {
    pub fn from_sddl(sddl: &str) -> std::io::Result<Self> {
        let text = wide(sddl);
        let mut descriptor: *mut core::ffi::c_void = std::ptr::null_mut();
        // SAFETY: a NUL-terminated SDDL string; the descriptor is freed on drop.
        if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), SDDL_REVISION_1, &mut descriptor, std::ptr::null_mut()) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }

    /// Attributes naming this descriptor, for a create call.
    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }
}

impl Drop for PipeSecurity {
    fn drop(&mut self) {
        // SAFETY: allocated by the system for this wrapper.
        unsafe { LocalFree(self.0.cast()) };
    }
}

/// A named pipe that admits only `owner_sid` (plus SYSTEM and the
/// service itself) and rejects remote clients.
pub struct NamedPipeListener {
    name: Vec<u16>,
    sddl: String,
    first: std::sync::Mutex<bool>,
}

impl NamedPipeListener {
    /// `owner_sid` is the desktop user whose vault this custodian holds.
    pub fn new(name: &str, owner_sid: &str) -> Self {
        Self {
            name: wide(name),
            sddl: owner_pipe_sddl(owner_sid),
            first: std::sync::Mutex::new(true),
        }
    }

    fn create(&self) -> std::io::Result<File> {
        let security = PipeSecurity::from_sddl(&self.sddl)?;
        let attributes = security.attributes();
        let mut first = self.first.lock().unwrap_or_else(|e| e.into_inner());
        let open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | if *first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
        // SAFETY: valid name and attributes for the duration of the call.
        let handle = unsafe {
            CreateNamedPipeW(self.name.as_ptr(), open_mode, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, PIPE_UNLIMITED_INSTANCES, 64 * 1024, 64 * 1024, 0, &attributes)
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        *first = false;
        // SAFETY: a fresh owned pipe handle.
        Ok(unsafe { File::from_raw_handle(handle as RawHandle) })
    }
}

impl Listener for NamedPipeListener {
    fn accept(&self) -> std::io::Result<Connection> {
        loop {
            let file = self.create()?;
            let handle = file.as_raw_handle() as HANDLE;
            // SAFETY: our own pipe instance; the wait completes the connect.
            match overlapped(handle, |op| unsafe { ConnectNamedPipe(handle, op) }) {
                Ok(_) => {}
                Err(error) if error.raw_os_error() == Some(ERROR_PIPE_CONNECTED as i32) => {}
                Err(error) => return Err(error),
            }
            // The DACL admits only the owner; the custodian's policy still
            // selects a principal from this peer and refuses anything else.
            // A client that cannot be identified is dropped, not the listener.
            match peer_facts::pipe_client_peer(handle) {
                Ok(peer) => {
                    return Ok(Connection {
                        stream: Box::new(PipeStream { file, server: true }),
                        peer,
                    });
                }
                Err(error) => eprintln!("djinn-custodian: refused an unidentified pipe client: {error}"),
            }
        }
    }
}

/// Grant `sids` query access to this process and its primary token, so a
/// pipe peer running as one of them can identify this process (an
/// `OpenProcess` for limited query, then `OpenProcessToken`). By default
/// both admit only the user, SYSTEM and the logon session, which leaves
/// out a service's virtual account and, for a service, the desktop user.
pub fn admit_identification(sids: &[String]) -> std::io::Result<()> {
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetSecurityInfo, NO_MULTIPLE_TRUSTEE,
        SE_KERNEL_OBJECT, SetEntriesInAclW, SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE, TOKEN_QUERY};
    use windows_sys::Win32::Storage::FileSystem::{READ_CONTROL, WRITE_DAC};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION};

    struct Local(*mut core::ffi::c_void);
    impl Drop for Local {
        fn drop(&mut self) {
            // SAFETY: allocated by the system for this wrapper, or null.
            unsafe { LocalFree(self.0.cast()) };
        }
    }
    fn grant(object: HANDLE, sids: &[Local], rights: u32) -> std::io::Result<()> {
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor: *mut core::ffi::c_void = std::ptr::null_mut();
        // SAFETY: valid out-pointers; the descriptor owns `dacl` and is freed below.
        let status = unsafe {
            GetSecurityInfo(object, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, std::ptr::null_mut(), std::ptr::null_mut(), &mut dacl, std::ptr::null_mut(), &mut descriptor)
        };
        let descriptor = Local(descriptor);
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }
        let entries: Vec<EXPLICIT_ACCESS_W> = sids
            .iter()
            .map(|sid| EXPLICIT_ACCESS_W {
                grfAccessPermissions: rights,
                grfAccessMode: GRANT_ACCESS,
                grfInheritance: NO_INHERITANCE,
                Trustee: TRUSTEE_W {
                    pMultipleTrustee: std::ptr::null_mut(),
                    MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                    TrusteeForm: TRUSTEE_IS_SID,
                    TrusteeType: TRUSTEE_IS_UNKNOWN,
                    ptstrName: sid.0.cast(),
                },
            })
            .collect();
        let mut merged: *mut ACL = std::ptr::null_mut();
        // SAFETY: `entries` and `dacl` are live for the call; `merged` is freed below.
        let status = unsafe { SetEntriesInAclW(entries.len() as u32, entries.as_ptr(), dacl, &mut merged) };
        let merged = Local(merged.cast());
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }
        // SAFETY: a handle with WRITE_DAC and a valid ACL.
        let status = unsafe {
            SetSecurityInfo(object, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, std::ptr::null_mut(), std::ptr::null_mut(), merged.0.cast(), std::ptr::null())
        };
        drop(descriptor);
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }

    let mut converted = Vec::with_capacity(sids.len());
    for sid in sids {
        let text = wide(sid);
        let mut raw: *mut core::ffi::c_void = std::ptr::null_mut();
        // SAFETY: a NUL-terminated SID string; freed by `Local`.
        if unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut raw) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        converted.push(Local(raw));
    }
    if converted.is_empty() {
        return Ok(());
    }
    // SAFETY: the pseudo-handle needs no closing and carries full access.
    grant(unsafe { GetCurrentProcess() }, &converted, PROCESS_QUERY_LIMITED_INFORMATION)?;
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: valid out-pointer; the token is closed by `Owned`.
    if unsafe { OpenProcessToken(GetCurrentProcess(), READ_CONTROL | WRITE_DAC, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let token = Owned(token);
    grant(token.0, &converted, TOKEN_QUERY)
}

/// The user SID of the client on a connected server pipe, read by
/// impersonating it at the level it allowed and reverting at once. Needs
/// nothing from the client, so it serves clients that cannot admit the
/// service to their process (OpenSSH's `ssh.exe`); it yields no image.
///
/// # Safety
/// `pipe` must be a live, connected server-side named pipe handle and
/// must remain open until this function returns.
pub unsafe fn impersonated_client_sid(pipe: HANDLE) -> std::io::Result<String> {
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, RevertToSelf, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
    use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

    // SAFETY: a connected server pipe handle.
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the impersonation token of this thread, opened as the
    // service itself; closed by `Owned`.
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
    let error = std::io::Error::last_os_error();
    // SAFETY: ends this thread's impersonation; a failure here would
    // leave the thread acting as the client, so it aborts.
    if unsafe { RevertToSelf() } == 0 {
        std::process::abort();
    }
    if opened == 0 {
        return Err(error);
    }
    let token = Owned(token);
    let mut len = 0u32;
    // SAFETY: a size query with a null buffer.
    unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut len) };
    let mut buffer = vec![0usize; (len as usize).div_ceil(std::mem::size_of::<usize>()).max(1)];
    // SAFETY: `buffer` holds `len` bytes, aligned for TOKEN_USER.
    if unsafe { GetTokenInformation(token.0, TokenUser, buffer.as_mut_ptr().cast(), len, &mut len) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the buffer now holds a TOKEN_USER.
    let user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: a valid SID; the string is freed below.
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a NUL-terminated string from the system.
    let sid = unsafe {
        let len = (0..).take_while(|&i| *text.add(i) != 0).count();
        String::from_utf16_lossy(std::slice::from_raw_parts(text, len))
    };
    // SAFETY: allocated by ConvertSidToStringSidW.
    unsafe { LocalFree(text.cast()) };
    Ok(sid)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client that has written nothing is still identified.
    #[test]
    fn a_server_reads_its_clients_sid_by_impersonation_before_any_data() {
        let user = crate::peer::current_user_sid().unwrap();
        let name = format!(r"\\.\pipe\custody-wire-impersonate-{}", std::process::id());
        let listener = NamedPipeListener::new(&name, &user);
        let server = listener.create().unwrap();
        let client = std::thread::spawn(move || NamedPipeConnector::new(&name).connect().map(|c| c.stream));
        let handle = server.as_raw_handle() as HANDLE;
        match overlapped(handle, |op| unsafe { ConnectNamedPipe(handle, op) }) {
            Ok(_) => {}
            Err(error) if error.raw_os_error() == Some(ERROR_PIPE_CONNECTED as i32) => {}
            Err(error) => panic!("connect: {error}"),
        }
        let _stream = client.join().unwrap().unwrap();
        // SAFETY: `server` owns this connected server handle through the call.
        assert_eq!(unsafe { impersonated_client_sid(handle) }.unwrap(), user);
    }
}

/// Connect to the custodian's pipe at identification-only impersonation.
pub struct NamedPipeConnector {
    name: Vec<u16>,
}

impl NamedPipeConnector {
    pub fn new(name: &str) -> Self {
        Self { name: wide(name) }
    }
}

impl Connector for NamedPipeConnector {
    fn connect(&self) -> std::io::Result<Connection> {
        for _ in 0..50 {
            // SAFETY: valid NUL-terminated name; the handle is owned below.
            let handle = unsafe {
                CreateFileW(self.name.as_ptr(), GENERIC_READ | GENERIC_WRITE, 0, std::ptr::null(), OPEN_EXISTING, FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, std::ptr::null_mut())
            };
            if handle == INVALID_HANDLE_VALUE {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) {
                    // SAFETY: `self.name` is a live NUL-terminated pipe name.
                    unsafe { WaitNamedPipeW(self.name.as_ptr(), 100) };
                    continue;
                }
                return Err(error);
            }
            // SAFETY: a fresh owned handle.
            let file = unsafe { File::from_raw_handle(handle as RawHandle) };
            let peer = peer_facts::pipe_server_peer(handle)?;
            return Ok(Connection {
                stream: Box::new(PipeStream { file, server: false }),
                peer,
            });
        }
        Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "the custodian pipe stayed busy"))
    }
}
