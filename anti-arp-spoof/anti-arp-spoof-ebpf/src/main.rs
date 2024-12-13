#![no_std]
#![no_main]

pub mod dhcp;
pub mod ptrs;
pub mod tc;
pub mod xdp;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
    //unsafe { core::hint::unreachable_unchecked() }
}
