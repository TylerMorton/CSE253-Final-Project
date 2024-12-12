#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IfaceMap {
    pub wifi_iface: Iface,
    pub eth_iface: Iface,
    pub plc_iface: Iface,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Iface {
    pub mac: [u8; 6],
    pub idx: u32,
    pub ip: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ClientMap {
    // for now we hard code this, later we would like nat
    pub ip: u32,
    pub mac: [u8; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IpMacMap {
    pub ip: u32,
    pub mac: [u8; 6],
}


#[cfg(feature = "user")]
unsafe impl aya::Pod for IfaceMap {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ClientMap {}

#[cfg(feature ="user")]
unsafe impl aya::Pod for IpMacMap {}

