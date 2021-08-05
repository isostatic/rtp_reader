#!/usr/bin/python3
# apt install python3-bpfcc
from bcc import BPF
from sys import argv 
from datetime import datetime
import socket
import os


device = "eno1"

b = BPF(src_file="rtpwatch.c")

fn = b.load_func("rtpwatch", BPF.XDP)

print(f"Bind to {device}")
b.attach_xdp(device, fn, 0)
print(f"Begining")

try:  
    b.trace_print()
except KeyboardInterrupt:  
    pass

b.remove_xdp(device, 0)
