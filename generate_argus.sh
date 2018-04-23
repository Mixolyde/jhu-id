#!/bin/bash

rm data/argusout_ports.csv

sudo argus -i eth0 -F /etc/nsm/pching-VM-eth1/argus.conf \
  -w - -r \
  ~/Downloads/99_w4/99_w4_mon_inside.tcpdump \
  | ra -L -1 -n -F rarc >> data/argusout_ports.csv

sudo argus -i eth0 -F /etc/nsm/pching-VM-eth1/argus.conf \
  -w - -r \
  ~/Downloads/99_w4/99_w4_wed_inside.tcpdump \
  | ra -L -1 -n -F rarc >> data/argusout_ports.csv

sudo argus -i eth0 -F /etc/nsm/pching-VM-eth1/argus.conf \
  -w - -r \
  ~/Downloads/99_w4/99_w4_thu_inside.tcpdump \
  | ra -L -1 -n -F rarc >> data/argusout_ports.csv

sudo argus -i eth0 -F /etc/nsm/pching-VM-eth1/argus.conf \
  -w - -r \
  ~/Downloads/99_w4/99_w4_fri_inside.tcpdump \
  | ra -L -1 -n -F rarc >> data/argusout_ports.csv

