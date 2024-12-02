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

Using eBPF for DPI we monitor all DHCP request/responses. on response we keep track of mac-ip mappings. If any noticable 

The problem here is spoofing mac addresses. However, we also look through the table. If a mac address already exists we block the mac address of the duplicate.

Dependencies & Requirements:

Experiment setup:

