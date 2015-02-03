#[allow(unstable)]
extern crate libc;
extern crate "posix-ipc" as ipc;
#[macro_use]
extern crate bitflags;

use std::os;
use std::ptr;
use std::default::Default;
use std::vec::Vec;
use std::mem;
use std::iter;
use std::num::FromPrimitive;

pub type Address = u64;
pub type Word = u64;

#[derive(Copy)]
pub enum Action {
  Allow,
  Kill
}

#[derive(Debug, Copy)]
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
  SetRegs = 13,
  Attach = 16,
  Detatch = 17,
  SetOptions = 0x4200,
  Seize = 0x4206
}

#[derive(Copy, Debug, FromPrimitive)]
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

impl Event {
    pub fn from_wait_status(st: i32) -> Option<Event> {
        let e: Option<Event> = FromPrimitive::from_i32(((st >> 8) & !5) >> 8);
        return e;
    }
}

#[derive(Copy, Default, Debug)]
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

pub fn setregs(pid: libc::pid_t, regs: &Registers) -> Result<libc::c_long, usize> {
    unsafe {
        let mut buf: *mut libc::c_void = mem::transmute(regs);
        raw (Request::SetRegs, pid, ptr::null_mut(), buf)
    }
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

#[derive(Copy, Debug)]
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

  pub fn write(&self) -> Result<libc::c_long, usize> {
      let mut regs = getregs(self.pid);
      regs.rdi = self.args[0];
      regs.rsi = self.args[1];
      regs.rdx = self.args[2];
      regs.rcx = self.args[3];
      regs.r8 = self.args[4];
      regs.r9 = self.args[5];
      regs.orig_rax = self.call;
      regs.rax = self.returnVal;
      setregs(self.pid, &regs)
  }
}

#[derive(Copy)]
pub struct Reader {
  pub pid: libc::pid_t
}

#[derive(Copy)]
pub struct Writer {
    pub pid: libc::pid_t
}

impl Writer {
    pub fn new(pid: libc::pid_t) -> Self {
        Writer {
            pid: pid
        }
    }

    pub fn poke_data(&self, address: Address, data: Word) -> Result<Word, usize> {
        match unsafe {
            raw (Request::PokeData, self.pid, address as *mut libc::c_void, ptr::null_mut())
        } {
            Err(e) => Err(e),
            Ok(r) => Ok(r as Word)
        }
    }

    pub fn write_object<T: Sized>(&self, address: Address, data: &T) -> Result<(), usize> {
        let mut buf = Vec::with_capacity(mem::size_of::<T>());
        unsafe {
            let tptr: *const T = data;
            let p: *const u8 = mem::transmute(tptr);
            for i in range(0, buf.capacity()) {
                buf.push(*p.offset(i as isize));
            }
        }

        Ok(())
    }

    pub fn write_data(&self, address: Address, buf: &Vec<u8>) -> Result<(), usize> {
        let max_addr = address + buf.capacity() as Address;
        let align_end = max_addr - (max_addr % mem::size_of::<Word>() as Address);
        for write_addr in iter::range_step(address as usize, align_end as usize, mem::size_of::<Word>()) {
            let mut d: Word = 0;
            for word_idx in iter::range(0, mem::size_of::<Word>()) {
                d = d << mem::size_of::<u8>();
                d += (buf[write_addr + word_idx] & 0xff) as Word;
            }
            self.poke_data(write_addr as Address, d).ok().expect("Could not poke");
        }
        if max_addr > align_end {
            let mut d: Word = 0;
            for word_idx in iter::range(0, mem::size_of::<Word>()) {
                d = d << mem::size_of::<u8>();
                d += (buf[align_end as usize + word_idx] & 0xff) as Word;
            }
            self.poke_data(align_end, d).ok().expect("Could not poke last byte");
        }
        Ok(())
    }
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
                let chr = ((d >> (word_idx*8) as usize) & 0xff) as u8;
                if chr == 0 {
                    end_of_str = true;
                    break 'finish;
                }
                buf.push (chr);
            }
        }
        if !end_of_str {
            let d = self.peek_data(align_end).ok().expect("Could not read");
            for word_idx in range(0, mem::size_of::<Word>()) {
                let chr = ((d >> (word_idx*8) as usize) & 0xff) as u8;
                if chr == 0 {
                    break;
                }
                buf.push (chr);
            }
        }
        return buf;
    }
}
