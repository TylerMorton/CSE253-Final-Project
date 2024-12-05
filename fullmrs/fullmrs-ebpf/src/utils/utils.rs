use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap},
};

pub const MAX_IPMACMAP_LEN: u32 = 100;
#[map]
pub static IPMACMAP: Array<u32> = Array::with_max_entries(1, 0);

#[map]
pub static IPMACMAP_ARRAY: Array<IpMac> = Array::with_max_entries(MAX_IPMACMAP_LEN, 0);
#[map]
pub static IPMACMAP_HASH: HashMap<[u8; 6], u32> = HashMap::with_max_entries(100, 0);

#[repr(C)]
pub struct IpMac {
    pub mac: [u8; 6],
    pub ip: u32,
}

pub fn ipmac_exists(mac: [u8; 6]) -> bool {
    unsafe { IPMACMAP_HASH.get(&mac).is_some() }
}

pub fn ipmac_get(mac: [u8; 6]) -> Option<u32> {
    unsafe {
        match IPMACMAP_HASH.get(&mac) {
            Some(val) => Some(*val),
            _ => None,
        }
    }
}

pub fn ipmac_insert(mac: [u8; 6], ip: u32, size: u32) -> Result<(), u32> {
    IPMACMAP_HASH.insert(&mac, &ip, 0).unwrap();
    if let Some(entry) = IPMACMAP_ARRAY.get_ptr_mut(size) {
        unsafe { *entry = IpMac { mac, ip } }
    }
    Ok(())
}
