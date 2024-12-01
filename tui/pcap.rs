use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, interfaces, MacAddr, NetworkInterface};
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::{ipv4::Ipv4Packet, ipv6::Ipv6Packet};
use pnet::packet::Packet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;

pub fn default_if() -> Result<NetworkInterface, &'static str> {
    // Get a vector with all network interfaces found
    let all_interfaces = interfaces();

    // Search for the default interface - the one that is
    // up, not loopback and has an IP.
    for interface in all_interfaces {
        if interface.is_up() && !interface.is_loopback() && !interface.ips.is_empty() {
            return Ok(interface);
        }
    }
    Err("Default interface not found")
}

fn handle_ipv4_packet<'ipv4>(
    ethernet: &'ipv4 EthernetPacket<'ipv4>,
) -> (Ipv4Addr, Ipv4Addr, IpNextHeaderProtocol, Ipv4Packet<'ipv4>) {
    let header = Ipv4Packet::new(ethernet.payload()).unwrap();
    (
        header.get_source(),
        header.get_destination(),
        header.get_next_level_protocol(),
        header,
    )
}
fn handle_ipv6_packet<'ipv6>(
    ethernet: &'ipv6 EthernetPacket<'ipv6>,
) -> (Ipv6Addr, Ipv6Addr, IpNextHeaderProtocol, Ipv6Packet<'ipv6>) {
    let header = Ipv6Packet::new(ethernet.payload()).unwrap();
    (
        header.get_source(),
        header.get_destination(),
        header.get_next_header(),
        header,
    )
}

fn handle_ethernet_packet(packet: &[u8]) -> (MacAddr, MacAddr, EtherType, EthernetPacket) {
    let header = EthernetPacket::new(packet).unwrap();
    (
        header.get_source(),
        header.get_destination(),
        header.get_ethertype(),
        header,
    )
}

fn handle_ip(iptype: IpNextHeaderProtocol) -> Result<String, ()> {
    let proto = match iptype {
        IpNextHeaderProtocols::Tcp => "TCP",
        IpNextHeaderProtocols::Udp => "UDP",
        IpNextHeaderProtocols::Icmpv6 => "ICMPv6",
        IpNextHeaderProtocols::Larp => "LARP",
        _ => return Err(()),
    };
    Ok(proto.to_string())
}

// Invoke as echo <interface name>
pub fn capture(capture_packets: Arc<Mutex<VecDeque<Vec<String>>>>) {
    let interface = default_if().unwrap();

    // Create a new channel, dealing with layer 2 packets
    let (tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                let (src_mac, dst_mac, ethertype, packet) = handle_ethernet_packet(packet);
                let mut packet_display = Vec::new();
                let mut proto = "ETHR".to_string();
                match ethertype {
                    EtherTypes::Arp => {}
                    EtherTypes::Ipv4 => {
                        let (src_ip, dst_ip, ipv4type, packet) = handle_ipv4_packet(&packet);
                        proto = handle_ip(ipv4type).unwrap_or("IPv4".to_string());
                        packet_display.push(dst_ip.to_string());
                        packet_display.push(src_ip.to_string());
                    }
                    EtherTypes::Ipv6 => {
                        let (src_ip, dst_ip, ipv6type, packet) = handle_ipv6_packet(&packet);
                        proto = handle_ip(ipv6type).unwrap_or("IPv6".to_string());
                        packet_display.push(dst_ip.to_string());
                        packet_display.push(src_ip.to_string());
                    }
                    //EtherTypes::Rarp => {},
                    //EtherTypes::Vlan => {},
                    _ => {}
                }
                packet_display.push(dst_mac.to_string());
                packet_display.push(src_mac.to_string());
                packet_display.push(proto);
                packet_display.reverse();
                let mut packets = capture_packets.lock().unwrap();
                if packets.len() >= 20 {
                    packets.push_front(packet_display);
                    packets.pop_back();
                } else {
                    packets.push_front(packet_display);
                }

                // Constructs a single packet, the same length as the one received,
                // using the provided closure. This allows the packet to be constructed
                // directly in the write buffer, without copying. If copying is not a
                // problem, you could also use send_to.
                //
                // The packet is sent once the closure has finished executing.
                /*
                tx.build_and_send(1, packet.packet().len(),
                    &mut |mut new_packet| {
                        let mut new_packet = MutableEthernetPacket::new(new_packet).unwrap();

                        // Create a clone of the original packet
                        new_packet.clone_from(&packet);

                        // Switch the source and destination
                        new_packet.set_source(packet.get_destination());
                        new_packet.set_destination(packet.get_source());
                });
                */
            }
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}
