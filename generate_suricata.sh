#!/bin/bash

rm data/eve.json

sudo suricata --user sguil --group sguil -c suricata.yaml \
  -l data -r ~/Downloads/99_w5/mon.inside.tcpdump --runmode=autofp \
  -F /etc/nsm/pching-VM-eth1/bpf-ids.conf

sudo suricata --user sguil --group sguil -c suricata.yaml \
  -l data -r ~/Downloads/99_w5/tue.inside.tcpdump --runmode=autofp \
  -F /etc/nsm/pching-VM-eth1/bpf-ids.conf

sudo suricata --user sguil --group sguil -c suricata.yaml \
  -l data -r ~/Downloads/99_w5/wed.inside.tcpdump --runmode=autofp \
  -F /etc/nsm/pching-VM-eth1/bpf-ids.conf

sudo suricata --user sguil --group sguil -c suricata.yaml \
  -l data -r ~/Downloads/99_w5/thu.inside.tcpdump --runmode=autofp \
  -F /etc/nsm/pching-VM-eth1/bpf-ids.conf

sudo suricata --user sguil --group sguil -c suricata.yaml \
  -l data -r ~/Downloads/99_w5/fri.inside.tcpdump --runmode=autofp \
  -F /etc/nsm/pching-VM-eth1/bpf-ids.conf
