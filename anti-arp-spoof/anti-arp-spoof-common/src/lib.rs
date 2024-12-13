#![no_std]

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Client {
    pub mac: [u8; 6],
    pub ip: u32,
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;
    unsafe impl aya::Pod for Client {}
}
