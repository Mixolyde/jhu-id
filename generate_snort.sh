#!/bin/bash

sudo snort -c /etc/nsm/pching-VM-eth1/snort.conf \
  -u sguil -g sguil \
  -F /etc/nsm/pching-VM-eth1/bpf-ids.conf \
  -l /nsm/sensor_data/pching-VM-eth1/snort-1 \
  --perfmon-file /nsm/sensor_data/pching-VM-eth1/snort-1.stats -U \
  --pcap-list="/home/pching442/Downloads/99_w4/99_w4_mon_inside.tcpdump /home/pching442/Downloads/99_w4/99_w4_wed_inside.tcpdump /home/pching442/Downloads/99_w4/99_w4_thu_inside.tcpdump /home/pching442/Downloads/99_w4/99_w4_fri_inside.tcpdump"
