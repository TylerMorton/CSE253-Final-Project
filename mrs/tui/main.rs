//! # [Ratatui] Original Demo example
//!
//! The latest version of this example is available in the [examples] folder in the repository.
//!
//! Please note that the examples are designed to be run against the `main` branch of the Github
//! repository. This means that you may not be able to compile with the latest release version on
//! crates.io, or the one that you have installed locally.
//!
//! See the [examples readme] for more information on finding examples that match the version of the
//! library you are using.
//!
//! [Ratatui]: https://github.com/ratatui/ratatui
//! [examples]: https://github.com/ratatui/ratatui/blob/main/examples
//! [examples readme]: https://github.com/ratatui/ratatui/blob/main/examples/README.md

use std::{error::Error, time::Duration};

use argh::FromArgs;
use std::sync::{Arc, Mutex};
use tokio::task;
use std::collections::VecDeque;

mod app;
mod crossterm;
mod pcap;
mod ui;

/// Demo
#[derive(Debug, FromArgs)]
struct Cli {
    /// time in ms between two ticks.
    //#[argh(option, default = "250")]
    //tick_rate: u64,
    #[argh(option, default = "30")]
    tick_rate: u64,
    /// whether unicode symbols are used to improve the overall look of the app
    #[argh(option, default = "true")]
    enhanced_graphics: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli: Cli = argh::from_env();
    let captured_packets: Arc<Mutex<VecDeque<Vec<String>>>> = Arc::new(Mutex::new(VecDeque::new()));
    let packets_clone = Arc::clone(&captured_packets);

    let mapped_ips = Arc<Mutex<VecDeque<u32>>> = Arc::new(Mutex::new(VecDeque::new()));
    let mapped_ips_cone = Arc::clone(&mapped_ips);

    task::spawn(async move { pcap::capture(packets_clone) });

    let tick_rate = Duration::from_millis(cli.tick_rate);
    crate::crossterm::run(tick_rate, cli.enhanced_graphics, captured_packets)?;
    Ok(())
}
