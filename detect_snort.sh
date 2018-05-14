#!/bin/bash

dart bin/snort_detect.dart data/master_identifications.list data/snort_alerts_99_w5.txt data/argusout_ports.csv data/eve.json
