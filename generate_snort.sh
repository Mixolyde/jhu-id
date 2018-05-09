#!/bin/bash

echo "Starting monday"
sudo snort -c /etc/nsm/pching-VM-eth1/snort.conf \
  -u sguil -g sguil \
  -F /etc/nsm/pching-VM-eth1/bpf-ids.conf \
  -l /nsm/sensor_data/pching-VM-eth1/snort-1 \
  -U \
  --perfmon-file /nsm/sensor_data/pching-VM-eth1/snort-1.stats -U \
  --pcap-list="/home/pching442/Downloads/99_w5/mon.inside.tcpdump"

echo "Starting tuesday"
sudo snort -c /etc/nsm/pching-VM-eth1/snort.conf \
  -u sguil -g sguil \
  -F /etc/nsm/pching-VM-eth1/bpf-ids.conf \
  -l /nsm/sensor_data/pching-VM-eth1/snort-1 \
  -U \
  --perfmon-file /nsm/sensor_data/pching-VM-eth1/snort-1.stats -U \
  --pcap-list="/home/pching442/Downloads/99_w5/tue.inside.tcpdump"

echo "Starting wednesday"
sudo snort -c /etc/nsm/pching-VM-eth1/snort.conf \
  -u sguil -g sguil \
  -F /etc/nsm/pching-VM-eth1/bpf-ids.conf \
  -l /nsm/sensor_data/pching-VM-eth1/snort-1 \
  -U \
  --perfmon-file /nsm/sensor_data/pching-VM-eth1/snort-1.stats -U \
  --pcap-list="/home/pching442/Downloads/99_w5/wed.inside.tcpdump"

echo "Starting thursday"
sudo snort -c /etc/nsm/pching-VM-eth1/snort.conf \
  -u sguil -g sguil \
  -F /etc/nsm/pching-VM-eth1/bpf-ids.conf \
  -l /nsm/sensor_data/pching-VM-eth1/snort-1 \
  -U \
  --perfmon-file /nsm/sensor_data/pching-VM-eth1/snort-1.stats -U \
  --pcap-list="/home/pching442/Downloads/99_w5/thu.inside.tcpdump"

echo "Starting friday"
sudo snort -c /etc/nsm/pching-VM-eth1/snort.conf \
  -u sguil -g sguil \
  -F /etc/nsm/pching-VM-eth1/bpf-ids.conf \
  -l /nsm/sensor_data/pching-VM-eth1/snort-1 \
  -U \
  --perfmon-file /nsm/sensor_data/pching-VM-eth1/snort-1.stats -U \
  --pcap-list="/home/pching442/Downloads/99_w5/fri.inside.tcpdump"
