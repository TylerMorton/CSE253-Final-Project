
#[inline(always)]
pub unsafe fn update_ipv4_csum(check: *mut u16, old_addr: u32, new_addr: u32) {
    let mut new_csum: u32 = !(*check as u32) & 0xffff;
    new_csum += (!old_addr >> 16) + (!old_addr & 0xffff);
    new_csum += (new_addr >> 16) + (new_addr & 0xffff);
    new_csum = (new_csum & 0xffff) + (new_csum >> 16);
    new_csum = (new_csum & 0xffff) + (new_csum >> 16);
    *check = !new_csum as u16;
}

#[inline(always)]
pub unsafe fn update_l4_csum(
    check: *mut u16,
    old_addr: u32,
    new_addr: u32,
    old_port: u16,
    new_port: u16,
) {
    let mut new_csum: u32 = !(*check as u32) & 0xffff;
    new_csum += (!old_addr >> 16) + (!old_addr & 0xffff);
    new_csum += (new_addr >> 16) + (new_addr & 0xffff);
    new_csum += (!old_port as u32 & 0xffff) + (new_port as u32 & 0xffff);
    new_csum = (new_csum & 0xffff) + (new_csum >> 16);
    new_csum = (new_csum & 0xffff) + (new_csum >> 16);
    *check = !new_csum as u16;
}
