#!/bin/bash

tcpreplay -t -i eth1 ~/Downloads/99_w4_mon_inside.tcpdump
tcpreplay -t -i eth1 ~/Downloads/99_w4_wed_inside.tcpdump
tcpreplay -t -i eth1 ~/Downloads/99_w4_thu_inside.tcpdump
tcpreplay -t -i eth1 ~/Downloads/99_w4_fri_inside.tcpdump

