# CSE253-Final-Project

TODO:
- [ ] Simulate an ARP Spoof
- [ ] Detect ARP Spoofing (Gratiutious or active)
- [ ] Simulate a DDOS
- [ ] Detect DDOS
- [ ] Verify encryptions over handover
- [ ] Have some sort of unique ids for sessions
- [ ] Active blocking + black/white lists

*Research Question* How can we secure Light Links system against ARP spoofing?

The major flaws that lead to ARP spoofing is the inherent flaws of ARP using no authentication. However, since our system acts as a central authority we can use a combination of DHCP and DAI to completely secure the system against ARP spoofs.

Using eBPF for DPI we monitor all DHCP discovery/offer/request/responses. On a response we keep track of mac-ip mappings assigned.

When arp requests and responses are received by the MRS router we utilize again DPI to perform a lookup against the Mac-IP map. If there is no match we drop the offending packet.

The problem here is what if the attacker is spoofing mac addresses as well. However, we also look through the table. If a mac address already exists we block the mac address of the duplicate. This could potentially lock a user out of the network but is a sacrifice to be made.

Dependencies & Requirements:
- dnsmasq
- hostapd
- ebpf [list of dependencies]
`sudo apt upgrade && sudo apt update && sudo apt install -y dnsmasq hostapd`

Experiment setup:
1. Install dependencies & download source
2. Configure static ip address:
```bash
sudo nano /etc/dhcpd.conf
```
add the following lines
```bash
interface wlan0
static ip_address=192.168.1.100/24
static routers=
static domain_name_servers=

3. DHCP server configuration
```bash
sudo nano /etc/dnsmasq.conf
```
interface=eth0
dhcp-range=,,

