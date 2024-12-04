#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::{PerCpuArray, RingBuf},
    programs::TcContext,
};
use aya_log_ebpf::info;
use fullmrs_common::tc::{PacketBuffer, MAX_MTU};

#[map]
static DATA: RingBuf = RingBuf::with_byte_size(256 * 1024, 0); // 256 KB

#[map]
static BUF: PerCpuArray<PacketBuffer> = PerCpuArray::with_max_entries(1, 0);

#[classifier()]
pub fn fullmrs_tc(ctx: TcContext) -> i32 {
    match try_tc_ringbuf(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tc_ringbuf(ctx: TcContext) -> Result<i32, i32> {
    // info!(&ctx, "received a packet");

    // TODO(vaodorvsky): This should be faster, but sadly it's annoying the
    // verifier.
    // if let Some(mut buf) = DATA.reserve::<PacketBuffer>(0) {
    //     let len = ctx.skb.len() as usize;
    //     let buf_inner = unsafe { &mut (*buf.as_mut_ptr()).buf };

    //     unsafe { (*buf.as_mut_ptr()).size = len };
    //     ctx.load_bytes(0, buf_inner).map_err(|_| TC_ACT_PIPE)?;

    //     buf.submit(0);
    // }

    // This is slower (`output` method is going to perform a copy)... and it
    // also annoys the verifier, FML.
    // let buf = unsafe {
    //     let ptr = BUF.get_ptr_mut(0).ok_or(0)?;
    //     &mut *ptr
    // };
    // if buf.buf.len() < MAX_MTU {
    //     return Err(TC_ACT_PIPE);
    // }
    // if ctx.data() + MAX_MTU > ctx.data_end() {
    //     return Err(TC_ACT_PIPE);
    // }

    // ctx.load_bytes(0, &mut buf.buf[..MAX_MTU])
    //     .map_err(|_| TC_ACT_PIPE)?;

    // DATA.output(buf, 0).map_err(|_| TC_ACT_PIPE)?;

    // Just send the struct for now, without filling it up with packet data.
    //
    /*
    let buf = unsafe {
        let ptr = BUF.get_ptr_mut(0).ok_or(0)?;
        &mut *ptr
    };
    if buf.buf.len() < MAX_MTU {
        return Err(TC_ACT_PIPE);
    }
    if ctx.data() + MAX_MTU > ctx.data_end() {
        return Err(TC_ACT_PIPE);
    }
    ctx.load_bytes(0, &mut buf.buf[..MAX_MTU])
        .map_err(|_| TC_ACT_PIPE)?;

    DATA.output(buf, 0).map_err(|_| TC_ACT_PIPE)?;
    */
    info!(&ctx, "hello");
    if let Some(mut buf) = DATA.reserve::<PacketBuffer>(0) {
        let mut pkt = PacketBuffer {
            size: 10,
            buf: [0; MAX_MTU],
        };
        let msg = "hello there";
        pkt.buf[..msg.len()].copy_from_slice(msg.as_bytes());
        let _ = buf.write(pkt);
        /*
        let len = ctx.skb.len() as usize;
        unsafe { (*buf.as_mut_ptr()).size = len };
        let buf_inner = unsafe { &mut (*buf.as_mut_ptr()).buf};
        ctx.load_bytes(0, buf_inner).map_err(|_| TC_ACT_PIPE)?;
        info!(&ctx, "submitting!");
        */
        buf.submit(0);
    }
    /*
     */

    Ok(TC_ACT_PIPE)
}
