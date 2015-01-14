extern crate libc;
extern crate "posix-ipc" as ipc;

use std::os;
use std::ptr;
use std::default::Default;
use std::vec::Vec;
use std::mem;
use std::iter;
use std::num::FromPrimitive;

pub type Address = u64;
pub type Word = u64;

pub enum Action {
  Allow,
  Kill
}

#[derive(Show)]
pub enum Request {
  TraceMe = 0,
  PeekText = 1,
  PeekData = 2,
  PeekUser = 3,
  PokeText = 4,
  PokeData = 5,
  PokeUser = 6,
  Continue = 7,
  Kill = 8,
  SingleStep = 9,
  GetRegs = 12,
  Attach = 16,
  Detatch = 17,
  SetOptions = 0x4200,
  Seize = 0x4206
}

#[derive(Show, FromPrimitive)]
pub enum Event {
  Fork = 1,
  VFork = 2,
  Clone = 3,
  Exec = 4,
  VForkDone = 5,
  Exit = 6,
  Seccomp = 7,
  Stop = 128
}

#[derive(Default, Show)]
pub struct Registers {
  pub r15: Word,
  pub r14: Word,
  pub r13: Word,
  pub r12: Word,
  pub rbp: Word,
  pub rbx: Word,
  pub r11: Word,
  pub r10: Word,
  pub r9: Word,
  pub r8: Word,
  pub rax: Word,
  pub rcx: Word,
  pub rdx: Word,
  pub rsi: Word,
  pub rdi: Word,
  pub orig_rax: Word,
  pub rip: Word,
  pub cs: Word,
  pub eflags: Word,
  pub rsp: Word,
  pub ss: Word,
  pub fs_base: Word,
  pub gs_base: Word,
  pub ds: Word,
  pub es: Word,
  pub fs: Word,
  pub gs: Word
}

bitflags! {
  flags Options: u32 {
    const SysGood = 1,
    const TraceFork = 1 << 1,
    const TraceVFork = 1 << 2,
    const TraceClone = 1 << 3,
    const TraceExec = 1 << 4,
    const TraceVForkDone = 1 << 5,
    const TraceExit = 1 << 6,
    const TraceSeccomp = 1 << 7,
    const ExitKill = 1 << 20
  }
}

pub fn setoptions(pid: libc::pid_t, opts: Options) -> Result<libc::c_long, usize> {
  unsafe {
    raw (Request::SetOptions, pid, ptr::null_mut(), opts.bits as *mut
    libc::c_void)
  }
}

pub fn getregs(pid: libc::pid_t) -> Registers {
  let mut buf: Registers = Default::default();
  let buf_mut: *mut Registers = &mut buf;

  unsafe {
    raw (Request::GetRegs, pid, ptr::null_mut(), buf_mut as *mut libc::c_void);
  }

  return buf;
}

pub fn seize(pid: libc::pid_t) -> Result<libc::c_long, usize> {
    unsafe {
        raw (Request::Seize, pid, ptr::null_mut(), ptr::null_mut())
    }
}

pub fn attach(pid: libc::pid_t) -> Result<libc::c_long, usize> {
  unsafe {
    raw (Request::Attach, pid, ptr::null_mut(), ptr::null_mut())
  }
}

pub fn release(pid: libc::pid_t, signal: ipc::signals::Signal) {
  unsafe {
    raw (Request::Detatch, pid, ptr::null_mut(), (signal as u32) as *mut libc::c_void);
  }
}

pub fn cont(pid: libc::pid_t, signal: ipc::signals::Signal) -> Result<libc::c_long, usize> {
  unsafe {
    raw (Request::Continue, pid, ptr::null_mut(), (signal as u32) as *mut libc::c_void)
  }
}

pub fn traceme() -> Result<libc::c_long, usize> {
  unsafe {
    raw (Request::TraceMe, 0, ptr::null_mut(), ptr::null_mut())
  }
}

unsafe fn raw(request: Request,
       pid: libc::pid_t,
       addr: *mut libc::c_void,
       data: *mut libc::c_void) -> Result<libc::c_long, usize> {
  let v = ptrace (request as libc::c_int, pid, addr, data);
  match v {
      -1 => Result::Err(os::errno()),
      _ => Result::Ok(v)
  }
}

extern {
  fn ptrace(request: libc::c_int,
            pid: libc::pid_t,
            addr: *mut libc::c_void,
            data: *mut libc::c_void) -> libc::c_long;
}

#[derive(Show)]
pub struct Syscall {
  pub args: [Word; 6],
  pub call: u64,
  pub pid: libc::pid_t,
  pub returnVal: Word
}

impl Syscall {
  pub fn from_pid(pid: libc::pid_t) -> Syscall {
    let regs = getregs (pid);
    Syscall {
      pid: pid,
      call: regs.orig_rax,
      args: [regs.rdi, regs.rsi, regs.rdx, regs.rcx, regs.r8, regs.r9],
      returnVal: 0
    }
  }
}

pub struct Reader {
  pub pid: libc::pid_t
}

impl Reader {
  pub fn new(pid: libc::pid_t) -> Reader {
    Reader {
      pid: pid
    }
  }

    pub fn peek_data(&self, address: Address) -> Result<Word, usize> {
        let l;
        unsafe {
            l = raw (Request::PeekData, self.pid, address as *mut libc::c_void, ptr::null_mut())
        }
        match l {
            Result::Err(e) => Result::Err(e),
            _ => Result::Ok(l.unwrap() as Word)
        }
    }

    pub fn read_string(&self, address: Address) -> Vec<u8> {
        let mut end_of_str = false;
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        let max_addr = address + buf.capacity() as Address;
        let align_end = max_addr - (max_addr % mem::size_of::<Word>() as Address);
        'finish: for read_addr in iter::range_step(address, align_end, mem::size_of::<Word>() as Address) {
            let d = self.peek_data(read_addr).ok().expect("Could not read");
            for word_idx in iter::range(0, mem::size_of::<Word>()) {
                let chr = ((d >> (word_idx*8) as uint) & 0xff) as u8;
                buf.push (chr);
                if chr == 0 {
                    end_of_str = true;
                    break 'finish;
                }
            }
        }
        if !end_of_str {
            let d = self.peek_data(align_end).ok().expect("Could not read");
            for word_idx in range(0, mem::size_of::<Word>()) {
                let chr = ((d >> (word_idx*8) as uint) & 0xff) as u8;
                buf.push (chr);
                if chr == 0 {
                    break;
                }
            }
        }
        return buf;
    }
}
