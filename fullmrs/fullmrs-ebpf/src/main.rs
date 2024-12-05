#![no_std]
#![no_main]

pub mod tc;
pub mod utils;
pub mod xdp;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
