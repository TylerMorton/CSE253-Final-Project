use anyhow::Context as _;
use aya::maps::RingBuf;
use aya::programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpFlags};
use clap::Parser;
use std::os::fd::AsRawFd;
#[rustfmt::skip]
use log::{debug, warn};
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use std::net::Ipv4Addr;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

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
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/fullmrs"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    // Load xdp
    let program: &mut Xdp = ebpf.program_mut("fullmrs_xdp").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
    //Load tc
    let _ = tc::qdisc_add_clsact(&opt.iface);
    let program: &mut SchedClassifier = ebpf.program_mut("fullmrs_tc").unwrap().try_into()?;
    program.load()?;
    program
        .attach(&opt.iface, TcAttachType::Egress)
        .context("failed to attach the TC program with default flags")?;

    let mut ring = RingBuf::try_from(ebpf.map_mut("DATA").unwrap())?;
    // Create poll
    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(2);
    let raw_fd = ring.as_raw_fd();
    // Register the listener
    poll.registry()
        .register(&mut SourceFd(&raw_fd), Token(0), Interest::READABLE)?;

    //TODO: let token = CancellationToken::new();
    loop {
        poll.poll(&mut events, None)?;
        for event in &events {
            debug!("event token: {:?}", event.token());
            if event.token() == Token(0) && event.is_readable() {
                if let Some(item) = ring.next() {
                    if item.len() < 4 {
                        continue;
                    }
                    let mut src_ip: [u8; 4] = [0; 4];
                    let data: &[u8] = item.as_ref();
                    src_ip[..4].copy_from_slice(&data[..4]);
                    let ip = Ipv4Addr::from_bits(u32::from_le_bytes(src_ip));
                    debug!("From tc-ebpf: {}", ip.to_string());
                }
            }
        }
    }
}
