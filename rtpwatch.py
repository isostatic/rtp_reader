#!/usr/bin/python3
# apt install python3-bpfcc
from bcc import BPF
from sys import argv 
from datetime import datetime
import socket
import struct
import os
import time
import ctypes as ct


PACKET_SIZE_BITS = 1370 * 8 

device = "eno1"

def dumpStats():
    dist = b.get_table("sharedhash")
    for k, v in dist.items():
        srcIP = socket.inet_ntoa(struct.pack('!I', k.srcip))
        dstIP = socket.inet_ntoa(struct.pack('!I', k.dstip))
        streamKey = str(srcIP) + ":" + str(k.srcport) + ">" + str(dstIP) + ":" + str(k.dstport)

        #streamName = bytearray(v.providerName, encoding="utf-8").decode()
        streamName = v.providerName.decode("latin") + "/" + v.serviceName.decode("latin")
        numPacketsSeen = v.packetnum;
        deltaNS = v.lastPacketTime - v.firstPacketTime
        seconds = deltaNS / 1000 / 1000 / 1000
        iprate = int((PACKET_SIZE_BITS * numPacketsSeen) / seconds) # bits per second
        iprate = int(iprate / 1000)/1000 # convert to mbit
        seconds = int(seconds)
        print(f"Stream {streamKey}={streamName}. {numPacketsSeen} pkts over last {seconds} seconds, errors={v.errors}. Stream at {iprate}Mbit");

class Data(ct.Structure):
    _fields_ = [
        ('lastPacketTime', ct.c_uint64),
        ('firstPacketTime', ct.c_uint64),
        ('packetnum', ct.c_uint64),
        ('lastSeqNum', ct.c_uint16),
        ('errors', ct.c_uint64),
        ('srcport', ct.c_uint16),
        ('dstport', ct.c_uint16),
        ('srcip', ct.c_uint32),
        ('dstip', ct.c_uint32),
        ('serviceName', ct.c_char * 31), # NB 31 is 1 higher than MAX_PROV_LEN defined in the ebpf
        ('providerName', ct.c_char * 31),
        ('prevSeqNum', ct.c_uint16),
        ('curSeqNum', ct.c_uint16),
        ('deltaTimeStamp', ct.c_uint64),
    ]

# Triggers whenever there's an RTP discontinuity
def rtp_error(cpu, data, size):
    data = ct.cast(data, ct.POINTER(Data)).contents
    srcIP = socket.inet_ntoa(struct.pack('!I', data.srcip))
    dstIP = socket.inet_ntoa(struct.pack('!I', data.dstip))
    streamKey = str(srcIP) + ":" + str(data.srcport) + ">" + str(dstIP) + ":" + str(data.dstport)

    numPacketsSeen = data.packetnum;
    deltaNS = data.lastPacketTime - data.firstPacketTime
    seconds = deltaNS / 1000 / 1000 / 1000
    if (seconds == 0):
        iprate = -1
    else:
        iprate = int((PACKET_SIZE_BITS * numPacketsSeen) / seconds) # bits per second
        iprate = int(iprate / 1000)/1000 # convert to mbit

    seconds = int(seconds)

    streamName = data.providerName.decode("latin") + "/" + data.serviceName.decode("latin")
    msGap = data.deltaTimeStamp / 1000
    print(f"ERROR in Stream {streamKey}={streamName}. {data.prevSeqNum} -> {data.curSeqNum} in {msGap}ms");

# Triggers whenever the stat counter is reset by the ebpf module (every few seconds)
def stat_reset(cpu, data, size):
    data = ct.cast(data, ct.POINTER(Data)).contents
    srcIP = socket.inet_ntoa(struct.pack('!I', data.srcip))
    dstIP = socket.inet_ntoa(struct.pack('!I', data.dstip))
    streamKey = str(srcIP) + ":" + str(data.srcport) + ">" + str(dstIP) + ":" + str(data.dstport)

    numPacketsSeen = data.packetnum;
    deltaNS = data.lastPacketTime - data.firstPacketTime
    seconds = deltaNS / 1000 / 1000 / 1000
    if (seconds == 0):
        iprate = -1
    else:
        iprate = int((PACKET_SIZE_BITS * numPacketsSeen) / seconds) # bits per second
        iprate = int(iprate / 1000)/1000 # convert to mbit

    seconds = int(seconds)

    streamName = data.providerName.decode("latin") + "/" + data.serviceName.decode("latin")
    print(f"Stream {streamKey}={streamName}. {numPacketsSeen} pkts over last {seconds} seconds, errors={data.errors}. Stream at {iprate}Mbit");

b = BPF(src_file="rtpwatch.c")

fn = b.load_func("rtpwatch", BPF.XDP)

print(f"Bind to {device}")
b.attach_xdp(device, fn, 0)
b['stats_perf'].open_perf_buffer(stat_reset)
b['error_perf'].open_perf_buffer(rtp_error)
print(f"Begining")

try:  
    while(1):
#        time.sleep(2)
        b.perf_buffer_poll()
#        dumpStats()

#    b.trace_print()
except KeyboardInterrupt:  
    print("FINAL DATA\n");
    dumpStats()
    pass

b.remove_xdp(device, 0)

