use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{Array, HashMap, PerfEventArray},
    programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpFlags},
    Bpf,
};
use aya_log::BpfLogger;
use get_if_addrs::get_if_addrs;
use log::{debug, info, warn};
use mac_address::MacAddress;
use mrs_common::{
    ClientMap, HandoverMode, HandoverParams, IfaceMap, IpMacMap, MediumSelection, UserParams,
};
use std::ptr::read;

use std::sync::{Arc, Mutex};
use std::collections::VecDeque;

use core::net::Ipv4Addr;
use tokio::signal::unix::{signal, SignalKind};

mod utils;
use utils::*;

pub fn load(eth_iface:String, wifi_iface:String, plc_iface:String) -> Result<Bpf, anyhow::Error> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/mrs"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/mrs"
    ))?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let _ = tc::qdisc_add_clsact(&eth_iface);

    let program: &mut SchedClassifier = bpf.program_mut("tc_egress").unwrap().try_into()?;
    program.load()?;
    program.attach(&eth_iface, TcAttachType::Egress)?;

    let eth_prog: &mut Xdp = bpf.program_mut("xdp_eth").unwrap().try_into()?;
    eth_prog.load()?;
    eth_prog.attach(&eth_iface, XdpFlags::default())
        .context("failed to attach the ETH XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    //todo: add programs in

    // load params map with the good stuff
    let mut ifaces: Array<_, IfaceMap> = Array::try_from(bpf.map_mut("IFACE_MAP").unwrap())?;

    let addrs = get_if_addrs()?;

    // set up the param map with the iface we want to redirect from
    //TODO: alright these ip things are getting kinda beefy, should rewrite more cleanly
    ifaces
        .set(
            0,
            IfaceMap {
                eth_iface: iface_by_name(&eth_iface, &addrs)?,
                wifi_iface: iface_by_name(&wifi_iface, &addrs)?,
                plc_iface: iface_by_name(&plc_iface, &addrs)?,
            },
            0,
        )
        .with_context(|| "Something went wrong when inserting into IfaceMap")?;

    let mut clients: Array<_, ClientMap> = Array::try_from(bpf.map_mut("CLIENT_MAP").unwrap())?;

    clients.set(
        0,
        ClientMap {
            // hard coded client address
            ip: Ipv4Addr::new(10, 42, 0, 114).to_bits().to_be(),
            mac: MacAddress::new([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).bytes(),
        },
        0,
    )?;

    //TODO: Handover params were never meant to be used like this. Instaed it was meant to be for
    //struct definition

    return Ok(bpf);
 }

#[repr(C)]
#[derive(Debug)]
pub struct KeyValue {
    key: [u8; 6],
    value: u32
}

pub async fn run(mut bpf: Bpf/*, mapped_ips: Arc<Mutex<VecDeque<u32>>>*/) -> Result<(), anyhow::Error> {
    let mut stream_int = signal(SignalKind::interrupt())?;
    let mut stream_quit = signal(SignalKind::quit())?;
    let mut handover_param = HandoverParams { val: 0 };
    let user_params = UserParams {
        //handover_mode: HandoverMode::Auto,
        handover_mode: HandoverMode::Manual(MediumSelection::Light),
    };
    loop {
        let mut handover_arg: Array<_, HandoverParams> =
            Array::try_from(bpf.map_mut("HANDOVER_MAP").unwrap())?;
        handover_arg.set(0, handover_param, 0)?;
        let mut user_params_map: Array<_, UserParams> =
            Array::try_from(bpf.map_mut("USER_PARAMS_MAP").unwrap())?;
        user_params_map.set(0, user_params, 0)?;
        let mut events = AsyncPerfEventArray::try_from(bpf.map("EVENTS").unwrap())?;
        for cpu in online_cpus()? {
            let mut buf = events.open(cpu, None)?;
        }

        let poll = poll_buffers(perf_buffers);
        // do the ring buf stuff
        info!("Waiting for Signals...");
        tokio::select! {
            _ = stream_int.recv() => {
                info!("Received SIGINT. Exiting...");
                return Ok(());
            },
            _ = stream_quit.recv() => {
                println!("Received SIGQUIT");
                handover_param = if handover_param.val == 0 {HandoverParams {
                    val: 1
                }} else {
                    HandoverParams {
                    val : 0}
                };
            },
            event = events.poll(1000) => {
                match event {
                    Ok(data) =>{
                    let key_value: KeyValue = unsafe { read(data.as_ptr() as *const _)};
                    println!("Received: key = {:?} value = {}", key_value.key, key_value.value);
                    },
                    Err(e) => {
                        eprintln!("Error receiving event {}", e);
                    }
                }
            }
        }
    }
        //stream_int.recv().await;
        //signal::ctrl_c().await?;
        info!("continuing the process ...");
        return Ok(());
    }
