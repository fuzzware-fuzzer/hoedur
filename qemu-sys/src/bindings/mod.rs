#[cfg(debug_assertions)]
pub mod debug {
    #[cfg(feature = "arm")]
    pub mod arm;
}
#[cfg(debug_assertions)]
pub use debug::*;

#[cfg(not(debug_assertions))]
pub mod release {
    #[cfg(feature = "arm")]
    pub mod arm;
}
#[cfg(not(debug_assertions))]
pub use release::*;

pub mod workaround {
    extern "C" {
        #[doc = " main_loop_wait: Run one iteration of the main loop."]
        #[doc = ""]
        #[doc = " If @nonblocking is true, poll for events, otherwise suspend until"]
        #[doc = " one actually occurs.  The main loop usually consists of a loop that"]
        #[doc = " repeatedly calls main_loop_wait(false)."]
        #[doc = ""]
        #[doc = " Main loop services include file descriptor callbacks, bottom halves"]
        #[doc = " and timers (defined in qemu/timer.h).  Bottom halves are similar to timers"]
        #[doc = " that execute immediately, but have a lower overhead and scheduling them"]
        #[doc = " is wait-free, thread-safe and signal-safe."]
        #[doc = ""]
        #[doc = " @nonblocking: Whether the caller should block until an event occurs."]
        pub fn main_loop_wait(nonblocking: ::std::os::raw::c_int);
    }
}
