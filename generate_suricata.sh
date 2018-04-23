#!/bin/bash

sudo suricata --user sguil --group sguil -c suricata.yaml -l data -r ~/Downloads/99_w4/ --runmode=autofp -F /etc/nsm/pching-VM-eth1/bpf-ids.conf
