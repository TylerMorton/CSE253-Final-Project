#![no_std]
#![no_main]

pub mod tc;
pub mod xdp;
pub mod ptrs;
pub mod dhcp;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
    //unsafe { core::hint::unreachable_unchecked() }
}

