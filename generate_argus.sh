#!/bin/bash

argus -i eth0 -F /etc/nsm/pching-VM-eth1/argus.conf \
  -w - -r \
  ~/Downloads/99_w4/99_w4_mon_inside.tcpdump \
  ~/Downloads/99_w4/99_w4_wed_inside.tcpdump \
  ~/Downloads/99_w4/99_w4_thu_inside.tcpdump \
  ~/Downloads/99_w4/99_w4_fri_inside.tcpdump \
  | ra -n -c "," > data/argusout_ports.csv
