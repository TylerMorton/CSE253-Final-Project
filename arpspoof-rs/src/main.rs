use pnet::datalink::{self, interfaces, Channel::Ethernet, MacAddr, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::{
    arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
    ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
};
use std::net::{IpAddr, Ipv4Addr};

pub fn default_if() -> Result<NetworkInterface, &'static str> {
    let all_interfaces = interfaces();

    for interface in all_interfaces {
        if interface.is_up() && !interface.is_loopback() && !interface.ips.is_empty() {
            return Ok(interface);
        }
    }
    Err("Default interface not found")
}

pub fn resolve(
    interface: NetworkInterface,
    ip: Ipv4Addr,
    mac: MacAddr,
    channel: datalink::Channel,
) -> bool {
    let (mut tx, mut rx) = match channel {
        Ethernet(tx, rx) => (tx, rx),
        _ => {
            panic!("Channel not supported")
        }
    };

    let mut arp_buffer: [u8; 28] = [0; 28];
    let mut arp_request = MutableArpPacket::new(&mut arp_buffer).unwrap();
    arp_request.set_operation(ArpOperations::Request);

    let sender_mac = interface.mac.unwrap();
    let sender_ip_if = interface.ips.first().unwrap();
    if !sender_ip_if.is_ipv4() {
        panic!("Sender ip is not IPV4. IP version not supported");
    }

    let sender_ip_addr = interface.ips.first().unwrap().ip();

    if let IpAddr::V4(sender_ip) = sender_ip_addr {
        arp_request.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_request.set_hw_addr_len(6);
        arp_request.set_proto_addr_len(4);
        arp_request.set_protocol_type(EtherTypes::Ipv4);

        arp_request.set_sender_hw_addr(sender_mac);
        arp_request.set_sender_proto_addr(sender_ip);

        arp_request.set_target_hw_addr(mac);
        arp_request.set_target_proto_addr(ip);
        let mut buffer: [u8; 42] = [0; 42];
        let mut ethernet = MutableEthernetPacket::new(&mut buffer).unwrap();
        ethernet.set_ethertype(EtherTypes::Ipv4);
        ethernet.set_source(sender_mac);
        ethernet.set_destination(mac);
        ethernet.set_payload(&arp_buffer);
        tx.send_to(&mut buffer, Some(interface));
        loop {
            if let Ok(packet) = rx.next() {
                let packet = EthernetPacket::new(packet).unwrap();
                if packet.get_ethertype() != EtherTypes::Arp {
                    continue;
                }
                let arp_response = ArpPacket::new(packet.payload()).unwrap();
                if arp_response.get_operation() == ArpOperations::Reply
                    && arp_response.get_target_hw_addr() == sender_mac
                    && arp_response.get_target_proto_addr() == sender_ip
                    && arp_response.get_sender_hw_addr() == mac
                    && arp_response.get_sender_proto_addr() == ip
                {
                    return true;
                }
            }
        }
    }
    false
}

fn main() {
    let interface = default_if().unwrap();
    let (tx, rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (rx, tx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(_e) => panic!("An error occured"),
    };
}
