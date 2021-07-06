#!/usr/bin/python3
import sys
import socket
import struct
import datetime
import argparse
import json
import time
from socket import htonl
from datetime import datetime

current_nano_time = lambda: int(round(time.time() * 1000000))
lastseq = {}
lastcc = {}
pidcount = {}
timestamp = 0;
starttime = 0;
statsEvery = 500

def parseRTP(key,data):
    global lastseq
    rtp_seq= getBigint(data[2:4])
    if (key not in lastseq):
        lastseq[key] = rtp_seq-1
        True;

    delta = rtp_seq - lastseq[key]
    if (delta == 1 or delta == -65535):
        # OK
#         print(key + " num:" + str(rtp_seq) + ":: OK")
        True;
    else:
        print(key + " RTP ERROR in " + timestamp + " error jump of " + str(delta) + " from " + str(lastseq[key]) + " to " + str(rtp_seq))
        True;
    lastseq[key] = rtp_seq

def parseTS(key,data):
    global lastcc
    global pidcount
    seqnum = lastseq[key]
#    print(lastcc)
    if (key not in lastcc):
        lastcc[key] = {}
    if (key not in pidcount):
        pidcount[key] = {}
#    print(lastcc)

    hdr = data[0:4]
    if (hdr[0] == 0x47):
        pidH = hdr[1] & 0x1F;
        pidL = hdr[2];
        pidB = (pidH,pidL)
        pidnum = int.from_bytes(pidB, "big")

        cc = hdr[3] & 0x0f; # Last 4 bytes
        adapt = hdr[3] >> 4 & 0x03; # adapation field
        # adaptation_field_control, 0 = reserved, 1=adaptation_field, payload only, 2=Adaptation_field only, no payload, 3=Adaptation_field followed by payload

        diff = 1

        if (adapt == 0 or adapt == 2):
            # The continuity_counter shall not be incremented when the adaptation_field_control of the packet equals '00' or '10'.
#            adapnum = str(pidnum) + ".adap"
#            if (adapnum not in pidcount[key]):
#                pidcount[key][adapnum] = 0
#            pidcount[key][adapnum] += 1
            return

        if (pidnum not in pidcount[key]):
            pidcount[key][pidnum] = 0

        if (pidnum == 8191):
#            print(key, timestamp, seqnum, "NULL PACKET")
            pidcount[key][pidnum] += 1
            return
        if (pidnum not in lastcc[key]):
            lastcc[key][pidnum] = -1

#        print(key, "STRT parse of PID",pidnum,"cc=",cc,"last=",lastcc[key][pidnum]);
        if (lastcc[key][pidnum] < 0):
            # start of CC
            True;
        else:
            diff = cc - lastcc[key][pidnum]
#            print(key, "COMPARE",cc,lastcc[key][pidnum],diff);
            if (diff == -15):
                diff = 1;
    
        if (diff != 1):
            print(key, "CC ERROR in " + str(timestamp) + " RTP=" + str(seqnum) + " - PID" + str(pidnum) + ". Jumped " + str(diff) + " from " + str(lastcc[key][pidnum]) + " to " + str(cc));

#        print(key,"PID ",pidnum,"=",hex(pidnum),"CC=",cc,"diff=",diff,"lastcc=",lastcc[key][pidnum])
        lastcc[key][pidnum] = cc
        pidcount[key][pidnum] += 1
#        print(key, "FINISHED parse of PID",pidnum,"cc=",cc,"last=",lastcc[key][pidnum]);
    else:
        print("SYNC BYTE INVALID")

def byte2ip(i):
    #return(str(i[2]) + "." + str(i[3]) + "." + str(i[0]) + "." + str(i[1]));
    return(str(i[0]) + "." + str(i[1]) + "." + str(i[2]) + "." + str(i[3]));

def printStatsAndReset(number):
    number = str(number)
    global pidcount
    print("== CURRENT STATS " + timestamp + " of last " + number + " packets ==")
    for stream in sorted(pidcount):
        for pid in sorted(pidcount[stream]):
            pid_str=str(pid)
            if (pid == 8191):
                pid_str = "8191 (NULL)"
            print("Stream:",stream,"Pid:",pid_str,"Count:",pidcount[stream][pid])
    pidcount = {}

def parseEther(eth_pkt, baseFilename, mediumType):
    global lastseq

    # If it's ethernet, format is
    # 0-5 -- srcmac
    # 6-11 -- dstmac
    # 12-13 -- type

    # if type = vlan
    # 14-17 == vlan num (and flags in MSB)

    # If type is linux, header is 20 bytes long
        
#    print("Got Ether packet of len",len(eth_pkt));
    ipStart = 14
    if (len(eth_pkt) == 0):
        return False

    if (mediumType == 1):
        # Ethernet
        # ethernet header packet
        eth_src = eth_pkt[0:6]
        eth_dst = eth_pkt[6:12]
        eth_type = eth_pkt[12:14]
        ipStart = 14
#        print("Ethernet type",eth_type);
        if (eth_type == b'\x81\x00'):
            vlan_num=getBigint(eth_pkt[14:16])
            ipStart = 18
        elif (eth_type == b'\x08\x00'):
            # Normal ethernet
            ipStart = 14
        else:
            print("UNKNOWN ethertype",eth_type);
            return False;
    elif (mediumType == 113):
        # Linux cooked capture (-i any etc)
        ipStart = 20
    else:
        print("UNKNOWN capture type",mediumType)
        return False;

    # Normal capture
    ip_pkt = eth_pkt[ipStart:]

#    print("Got IP packet of len",len(ip_pkt))
    ip_hdr = ip_pkt[0:20]
    udp_pkt = ip_pkt[20:]

    srcip = byte2ip(ip_hdr[12:16])
    dstip = byte2ip(ip_hdr[16:20])

#    print("Got IP packet ",srcip,dstip);
    srcport = getBigint(udp_pkt[0:2])
    dstport = getBigint(udp_pkt[2:4])
    udplen = getBigint(udp_pkt[4:6])

    data = udp_pkt[8:]
    if ((udplen - 8) == len(data) and udplen == 1336):
        # OK, looks like this is the RTP payload
        ts_data = data[12:]
        stream_key = srcip + ":" + str(srcport) + ">" + dstip + ":" + str(dstport);
        parseRTP(stream_key, data)
        # 7 TS entries
#        print("START PARSE OF ",stream_key)
        for i in range(7):
            base = i * 188
            parseTS(stream_key,ts_data[base:base+188])

        # Save to TS
        if (baseFilename == None):
            True;
        else:
            ofname = baseFilename + "." + srcip + "." + str(srcport) + "_" + dstip + "." + str(dstport)  + ".ts";
#        print("Writing to ", ofname)
            oh = open(ofname,"ab");
            oh.write(ts_data);
            oh.close()
    else:
        True;
        # Not an RTP packet with 7x188 byte TS
#        print("ERROR in packet ",srcip,srcport,dstip,dstport,"act len=",len(data),"claimed len",udplen)
    return True
    

def readPacket(fh, baseFilename, mediumType):
    global timestamp,starttime
    header = bytearray(fh.read(16))
#    print("READ PACKET, bytes=",len(header))
    unix_time = getint(header[0:4])
    timestamp = datetime.utcfromtimestamp(unix_time).strftime('%Y-%m-%d %H:%M:%S') + "." + str(getint(header[4:8]))
    if (starttime == 0):
        starttime = timestamp;
#    print(timestamp)
#    print("timestamp",getint(header[0:4]),getint(header[4:8]))
#    print("cap",getint(header[8:12]),"/",getint(header[12:16]))
    toCap = getint(header[8:12]);
    return parseEther(fh.read(toCap), baseFilename, mediumType)
    
def getBigint(i):
    return int.from_bytes(i, byteorder='big', signed=False)

def getint(i):
    return int.from_bytes(i, byteorder='little', signed=False)

def run(capfile, destfile):
    fh = sys.stdin.buffer
    if (capfile == None):
        print("Read from STDIN");
        capfile = "STDIN"
    else:
        print("Read from ",capfile);
        fh = open(capfile, 'rb')
#    with open(capfile, 'rb') as fh:
    if (True):
        header = fh.read(24)
#        print("magic",hex(getint(header[0:4])))
#        print("maj",hex(getint(header[4:6])))
#        print("min",hex(getint(header[6:8])))
#        print("tz",hex(getint(header[8:12])))
#        print("sigfigs",hex(getint(header[12:16])))
#        print("snaplen",hex(getint(header[16:20])))
        captype = getint(header[20:24])
#        print("linktype.20",header[20])
#        print("linktype.21",header[21])
#        print("linktype.22",header[22])
#        print("linktype.23",header[23])
#        print("linktype.24",header[24])

#        print("Capture type:",captype)
        # 1 = ethernet
        # 113 = linux
        num=0
        while readPacket(fh, destfile, captype):
            num = num + 1
            if (statsEvery > 0 and num % statsEvery == 0):
                printStatsAndReset(num)
                num = 0
            True;
        print("Parse of " + capfile + " from " + starttime + " complete",num,"packets read")
        printStatsAndReset(num)
        if (destfile != None):
            print("TS dumped to "+destfile+".*.ts")

# sudo tcpdump -i ens1f1 udp port 6204 or port 6205 or port 6206 -w - | ./dumpts.py -s 20000
# ./dumpts.py -i cap.cap
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--in-file', help="File to read from (none=stdin)")
    parser.add_argument('-o', '--out-file', help="Root of file to write to (none=dontwrite)")
    parser.add_argument('-s', '--stats-every', type=int, help="Show and reset stats every n packets", default=0)
    args = parser.parse_args()
    statsEvery = args.stats_every
    run(args.in_file, args.out_file)
    
