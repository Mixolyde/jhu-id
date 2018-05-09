#!/bin/bash

rm data/argusout_ports.csv

sudo argus -i eth0 -F /etc/nsm/pching-VM-eth1/argus.conf \
  -w - -r \
  ~/Downloads/99_w5/mon.inside.tcpdump \
  | ra -L -1 -n -F rarc >> data/argusout_ports.csv

sudo argus -i eth0 -F /etc/nsm/pching-VM-eth1/argus.conf \
  -w - -r \
  ~/Downloads/99_w5/tue.inside.tcpdump \
  | ra -L -1 -n -F rarc >> data/argusout_ports.csv

sudo argus -i eth0 -F /etc/nsm/pching-VM-eth1/argus.conf \
  -w - -r \
  ~/Downloads/99_w5/wed.inside.tcpdump \
  | ra -L -1 -n -F rarc >> data/argusout_ports.csv

sudo argus -i eth0 -F /etc/nsm/pching-VM-eth1/argus.conf \
  -w - -r \
  ~/Downloads/99_w5/thu.inside.tcpdump \
  | ra -L -1 -n -F rarc >> data/argusout_ports.csv

sudo argus -i eth0 -F /etc/nsm/pching-VM-eth1/argus.conf \
  -w - -r \
  ~/Downloads/99_w5/fri.inside.tcpdump \
  | ra -L -1 -n -F rarc >> data/argusout_ports.csv

