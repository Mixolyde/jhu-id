#!/bin/bash

dart bin/snort_detect.dart data/master_identifications.list \
  data/snort_alerts.txt \ 
  data/argusout_ports.csv \
  data/eve.json
