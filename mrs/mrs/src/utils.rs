use std::ffi::CString;

use anyhow::{anyhow, bail, Result};
use get_if_addrs::Interface;
use mac_address::mac_address_by_name;
use mrs_common::Iface;

// sadly we cant impl this onto the iface struct since that lives in mrs-common, and that
// crate doesnt have access to the std library
pub fn iface_by_name(name: &str, addrs: &[Interface]) -> Result<Iface> {
    Ok(Iface {
        idx: iface_nametoindex(name).ok_or(anyhow!(format!("unable to find index of {}", name)))?,
        mac: mac_address_by_name(name)?
            .ok_or(anyhow!(format!("unable to get mac address of {}", name)))?
            .bytes(),
        ip: match addrs
            .to_owned()
            .clone()
            .into_iter()
            .filter(|addr| addr.name == name)
            .collect::<Vec<Interface>>()
            .first()
            .ok_or(anyhow!(format!(
                "Could not determine ip address for {}",
                name
            )))?
            .ip()
        {
            std::net::IpAddr::V4(addr) => u32::from_be_bytes(addr.octets()),
            std::net::IpAddr::V6(_) => {
                bail!(format!("{} has an ipV6 address, must havn ipV4", name))
            }
        },
    })
}

fn iface_nametoindex(ifname: &str) -> Option<u32> {
    let ifname_cstring = CString::new(ifname).ok()?;
    let index = unsafe { libc::if_nametoindex(ifname_cstring.as_ptr()) };

    if index == 0 {
        None
    } else {
        Some(index as u32)
    }
}
