#!/bin/bash

rm data/eve.json

sudo suricata --user sguil --group sguil -c suricata.yaml \
  -l data -r ~/Downloads/99_w4/99_w4_mon_inside.tcpdump --runmode=autofp \
  -F /etc/nsm/pching-VM-eth1/bpf-ids.conf

sudo suricata --user sguil --group sguil -c suricata.yaml \
  -l data -r ~/Downloads/99_w4/99_w4_wed_inside.tcpdump --runmode=autofp \
  -F /etc/nsm/pching-VM-eth1/bpf-ids.conf

sudo suricata --user sguil --group sguil -c suricata.yaml \
  -l data -r ~/Downloads/99_w4/99_w4_thu_inside.tcpdump --runmode=autofp \
  -F /etc/nsm/pching-VM-eth1/bpf-ids.conf

sudo suricata --user sguil --group sguil -c suricata.yaml \
  -l data -r ~/Downloads/99_w4/99_w4_fri_inside.tcpdump --runmode=autofp \
  -F /etc/nsm/pching-VM-eth1/bpf-ids.conf
