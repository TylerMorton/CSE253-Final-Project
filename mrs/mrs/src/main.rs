use anyhow::{Context, Result};
use aya::maps::Array;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use get_if_addrs::get_if_addrs;
use log::{debug, info, warn};
use mac_address::MacAddress;
use mrs_common::{IpMacMap, ClientMap, HandoverMode, HandoverParams, IfaceMap, MediumSelection, UserParams};

use tokio::signal::unix::{signal, SignalKind};

mod utils;
use utils::*;

use clap::Parser;
use core::net::Ipv4Addr;

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(short, long)]
    eth_iface: String,

    #[clap(short, long)]
    wifi_iface: String,

    #[clap(short, long)]
    plc_iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    let mut stream_int = signal(SignalKind::interrupt())?;
    let mut stream_quit = signal(SignalKind::quit())?;
    let mut handover_param = HandoverParams { val: 0 };
    let user_params = UserParams {
        //handover_mode: HandoverMode::Auto,
        handover_mode: HandoverMode::Manual(MediumSelection::Light),
    };
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

    let eth_prog: &mut Xdp = bpf.program_mut("xdp_eth").unwrap().try_into()?;
    eth_prog.load()?;
    eth_prog.attach(&opt.eth_iface, XdpFlags::default())
        .context("failed to attach the ETH XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    //   let plc_prog: &mut Xdp = bpf.program_mut("xdp_plc").unwrap().try_into()?;
    //   plc_prog.load()?;
    //   plc_prog.attach(&opt.plc_iface, XdpFlags::default())
    //      .context("failed to attach the PLC XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    //   let wifi_prog: &mut Xdp = bpf.program_mut("xdp_wifi").unwrap().try_into()?;
    //   wifi_prog.load()?;
    //   wifi_prog.attach(&opt.wifi_iface, XdpFlags::default())
    //       .context("failed to attach the WIFI XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    // load params map with the good stuff
    let mut ifaces: Array<_, IfaceMap> = Array::try_from(bpf.map_mut("IFACE_MAP").unwrap())?;

    let addrs = get_if_addrs()?;

    // set up the param map with the iface we want to redirect from
    //TODO: alright these ip things are getting kinda beefy, should rewrite more cleanly
    ifaces
        .set(
            0,
            IfaceMap {
                eth_iface: iface_by_name(&opt.eth_iface, &addrs)?,
                wifi_iface: iface_by_name(&opt.wifi_iface, &addrs)?,
                plc_iface: iface_by_name(&opt.plc_iface, &addrs)?,
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

    loop {
        let mut handover_arg: Array<_, HandoverParams> =
            Array::try_from(bpf.map_mut("HANDOVER_MAP").unwrap())?;
        handover_arg.set(0, handover_param, 0)?;
        let mut user_params_map: Array<_, UserParams> =
            Array::try_from(bpf.map_mut("USER_PARAMS_MAP").unwrap())?;
        user_params_map.set(0, user_params, 0)?;
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
        }
        //stream_int.recv().await;
        //signal::ctrl_c().await?;
        info!("continuing the process ...");
    }
}
