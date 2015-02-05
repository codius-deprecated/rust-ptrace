#![feature(libc, std_misc)]
extern crate libc;
extern crate ptrace;
extern crate "posix-ipc" as ipc;

use std::ffi::CString;
use std::os;
use std::ptr;

#[test]
fn test_attach_detach() {
    let pid = fork_and_halt();
    assert!(match ptrace::attach(pid) { Ok(_) => true, _ => false });
    unsafe { waitpid(pid, ptr::null_mut(), 0) };
    assert!(match ptrace::release(pid, ipc::signals::Signal::None) { Ok(_) => true, _ => false });
}

#[test]
fn test_read() {
    let (buf_addr, pid) = fork_with_buffer("foobar");
    let reader = ptrace::Reader::new(pid);
    match reader.peek_data(unsafe { buf_addr.offset(3) } as u64) {
        Ok(v) => assert_eq!((v & 0xff) as u8, 'b' as u8),
        Err(_) => panic!("Error while reading: {:?}", os::last_os_error())
    }
}

#[test]
fn test_read_string() {
    let (buf_addr, pid) = fork_with_buffer("foobar");
    let reader = ptrace::Reader::new(pid);
    match reader.read_string(buf_addr as u64) {
        Ok(v) =>
            assert_eq!(v, vec!('f' as u8, 'o' as u8, 'o' as u8, 'b' as u8, 'a' as u8, 'r' as u8)),
        Err(_) =>
            panic!("Error while reading string: {:?}", os::last_os_error())
    }
}

#[test]
fn test_write() {
    let (buf_addr, pid) = fork_with_buffer("foobar");
    let foo_word = 0x0123456789abcdef;

    let writer = ptrace::Writer::new(pid);
    match writer.poke_data(buf_addr as u64, foo_word) {
        Ok(_) => {
            let reader = ptrace::Reader::new(pid);
            let v = reader.peek_data(buf_addr as u64).ok().expect("Could not read back word");
            assert_eq!(v, foo_word);
        },
        Err(_) =>
            panic!("Error while writing char: {:?}", os::last_os_error())
    }
}

#[test]
// Test that we only overwrite the first few bytes, nothing more or less.
fn test_write_small_buf() {
    use std::str;
    let (buf_addr, pid) = fork_with_buffer("foobar and then some");
    let writer = ptrace::Writer::new(pid);
    let buf = vec!('F' as u8, 'O' as u8, 'O' as u8, 'B' as u8, 'A' as u8, 'R' as u8);
    match writer.write_data(buf_addr as u64, &buf) {
        Ok(_) => {
            let reader = ptrace::Reader::new(pid);
            let v = reader.read_string(buf_addr as u64).ok().expect("Could not read back buffer");
            assert_eq!(str::from_utf8(v.as_slice()), Ok("FOOBAR and then some"));
        },
        Err(_) =>
            panic!("Error while writing buffer: {:?}", os::last_os_error())
    }
}

#[test]
// Test that we only overwrite the first few words, nothing more or less.
fn test_write_large_buf() {
    use std::str;
    let s = "foo bar baz frob fritz friddle";
    let (buf_addr, pid) = fork_with_buffer(s);
    let writer = ptrace::Writer::new(pid);
    let mut buf: Vec<u8> = Vec::new();
    buf.push_all("FRIDDLE FRITZ FROB BAZ BAR FOO".as_bytes());
    match writer.write_data(buf_addr as u64, &buf) {
        Ok(_) => {
            let reader = ptrace::Reader::new(pid);
            let v = reader.read_string(buf_addr as u64).ok().expect("Could not read back buffer");
            assert_eq!(str::from_utf8(v.as_slice()), str::from_utf8(buf.as_slice()));
        },
        Err(_) =>
            panic!("Error while writing buffer: {:?}", os::last_os_error())
    }
}

fn fork_with_buffer(buf: &str) -> (*const libc::c_char, libc::c_int) {
    let buf = CString::from_slice(buf.as_bytes());
    let buf_addr: *const libc::c_char = buf.as_ptr();
    let pid = fork_and_halt();
    ptrace::attach(pid).ok().expect("Could not attach to child");
    unsafe { waitpid(pid, ptr::null_mut(), 0) };
    return (buf_addr, pid);
}

fn fork_and_halt() -> libc::c_int {
    match unsafe { fork() } {
        0 => {
            loop {
                unsafe { raise(19) };
            }
        },
        v => v
    }
}

extern "C" {
    fn fork() -> libc::pid_t;
    fn raise(signal: libc::c_int) -> libc::c_int;
    fn waitpid(pid: libc::pid_t, status: *mut libc::c_int, options: libc::c_int) -> libc::c_int;
}
