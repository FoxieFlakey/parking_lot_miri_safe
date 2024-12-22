// Copyright 2016 Amanieu d'Antras
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::{
    ptr,
    sync::atomic::{AtomicI32, Ordering},
};
use std::thread;
use std::time::Instant;

fn errno() -> libc::c_int {
    #[cfg(target_os = "linux")]
    unsafe {
        *libc::__errno_location()
    }
    #[cfg(target_os = "android")]
    unsafe {
        *libc::__errno()
    }
}

// Helper type for putting a thread to sleep until some other thread wakes it up
pub struct ThreadParker {
    futex: AtomicI32,
}

impl super::ThreadParkerT for ThreadParker {
    type UnparkHandle = UnparkHandle;

    const IS_CHEAP_TO_CONSTRUCT: bool = true;

    #[inline]
    fn new() -> ThreadParker {
        ThreadParker {
            futex: AtomicI32::new(0),
        }
    }

    #[inline]
    unsafe fn prepare_park(&self) {
        self.futex.store(1, Ordering::Relaxed);
    }

    #[inline]
    unsafe fn timed_out(&self) -> bool {
        self.futex.load(Ordering::Relaxed) != 0
    }

    #[inline]
    unsafe fn park(&self) {
        while self.futex.load(Ordering::Acquire) != 0 {
            self.futex_wait(None);
        }
    }

    #[inline]
    unsafe fn park_until(&self, timeout: Instant) -> bool {
        while self.futex.load(Ordering::Acquire) != 0 {
            let now = Instant::now();
            if timeout <= now {
                return false;
            }
            let diff = timeout - now;
            let diff_secs = diff.as_secs().try_into();
            let diff_subsec_nanos = diff.subsec_nanos().try_into();
            if diff_secs.is_err() || diff_subsec_nanos.is_err() {
                // Timeout overflowed, just sleep indefinitely
                self.park();
                return true;
            }
            // SAFETY: libc::timespec is zero initializable.
            let mut ts: libc::timespec = std::mem::zeroed();
            ts.tv_sec = diff_secs.unwrap();
            ts.tv_nsec = diff_subsec_nanos.unwrap();
            self.futex_wait(Some(ts));
        }
        true
    }

    // Locks the parker to prevent the target thread from exiting. This is
    // necessary to ensure that thread-local ThreadData objects remain valid.
    // This should be called while holding the queue lock.
    #[inline]
    unsafe fn unpark_lock(&self) -> UnparkHandle {
        // We don't need to lock anything, just clear the state
        self.futex.store(0, Ordering::Release);

        UnparkHandle { futex: &self.futex }
    }
}

impl ThreadParker {
    #[inline]
    fn futex_wait(&self, ts: Option<libc::timespec>) {
        let ts_ptr = ts
            .as_ref()
            .map(ptr::from_ref)
            .unwrap_or(ptr::null());
        let r = unsafe {
            libc::syscall(
                libc::SYS_futex,
                &self.futex,
                libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
                1,
                ts_ptr,
            )
        };
        debug_assert!(r == 0 || r == -1);
        if r == -1 {
            debug_assert!(
                errno() == libc::EINTR
                    || errno() == libc::EAGAIN
                    || (ts.is_some() && errno() == libc::ETIMEDOUT)
            );
        }
    }
}

pub struct UnparkHandle {
    futex: *const AtomicI32,
}

impl super::UnparkHandleT for UnparkHandle {
    #[inline]
    unsafe fn unpark(self) {
        // The thread data may have been freed at this point, but it doesn't
        // matter since the syscall will just return EFAULT in that case.
        let r = libc::syscall(
            libc::SYS_futex,
            self.futex,
            libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
            1,
        );
        debug_assert!(r == 0 || r == 1 || r == -1);
        if r == -1 {
            debug_assert_eq!(errno(), libc::EFAULT);
        }
    }
}

#[inline]
pub fn thread_yield() {
    thread::yield_now();
}
