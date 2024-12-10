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
lastts = {}
lastcc = {}
pidcount = {}
tsdiffcount = {}
timestamp = 0;
unix_time = 0
unix_time_high = 0
rtp_us = 0.0
last_stat_print = 0

starttime = 0;
statsEvery = 500

lastrtpts = {}
lastpcrrtp = {}
lastpcrbase = {}
lastpcrext = {}
pcrdiffcount = {}

current_pat = {}

svctable = {}
svctable["Service"] = {}
svctable["Provider"] = {}

log_base= ""


def STATS(line):
    if (log_base == ""):
        print(line)
    else:
        date = datetime.utcfromtimestamp(unix_time).strftime('%Y-%m-%d')
        fh = open(log_base + "." + date + ".STATS.log", "a")
        fh.write(line + "\n");
        fh.close()

def ERROR(line):
    OUTPUT("ERROR",line)

def WARNING(line):
    OUTPUT("WARNING",line)

def INFO(line):
    OUTPUT("INFO",line)

def DEBUG(line):
    #OUTPUT("DEBUG",line)
    ""

def OUTPUT(level,line):
    if (timestamp == 0 or log_base == ""):
        print(level,timestamp,line)
    else:
        date = datetime.utcfromtimestamp(unix_time).strftime('%Y-%m-%d')
        fh = open(log_base + "."+date + "." + level+".log", "a")
        fh.write(str(timestamp) + " " + line + "\n");
        fh.close()

def bytes2hexstream(bytarr):
    tor = ""
    for b in bytarr:
        tor += hex(b)[2:]
    return tor

def bytes2hex(bytarr, padto=0):
    tor = ""
    base = ""
    for b in bytarr:
        toadd = hex(b)[2:]
        if (len(toadd)) == 1:
            toadd = "0" + toadd
        tor += toadd
        base += toadd
        if (len(base) > 0 and len(base) % 8 == 0):
            tor += "."

    while (len(base) < padto):
        tor = "0" + tor
        
    return "0x" + tor

def getStreamName(stream):
    streamname = ""
    if (stream in svctable["Provider"]):
        if (len(svctable["Provider"][stream]["name"])):
            streamname += svctable["Provider"][stream]["name"] + "//"

    if (stream in svctable["Service"]):
        streamname += svctable["Service"][stream]["name"] 
    return streamname

def parseRTP(key,data):
    global lastseq
    global lastts
    global tsdiffcount


    delta_rtp_us = -1
    if (key in lastrtpts):
        delta_rtp_us = rtp_us - lastrtpts[key]["last"]
    else:
        lastrtpts[key] = {}
        lastrtpts[key]["last"] = rtp_us
        lastrtpts[key]["min"] = 999999999999
        lastrtpts[key]["max"] = 0
        lastrtpts[key]["num"] = 0
        lastrtpts[key]["start"] = -1

    if (lastrtpts[key]["start"] < 0):
        lastrtpts[key]["start"] = rtp_us

    lastrtpts[key]["last"] = rtp_us
    lastrtpts[key]["num"] += 1

    if (delta_rtp_us >= 0 and delta_rtp_us < lastrtpts[key]["min"]):
        lastrtpts[key]["min"] = delta_rtp_us

    if (delta_rtp_us >= 0 and delta_rtp_us > lastrtpts[key]["max"]):
        lastrtpts[key]["max"] = delta_rtp_us

    rtp_avg = (lastrtpts[key]["last"]-lastrtpts[key]["start"])/lastrtpts[key]["num"]
    rtp_timeperiod_sec = int((lastrtpts[key]["last"]-lastrtpts[key]["start"])/10000)/100

    rtp_seq= getBigint(data[2:4])

    rtp_ts= getBigint(data[4:8])
    #print(key,timestamp,"Got RTP packet (",str(rtp_seq)," at rtp_us=" + str(rtp_us) + " after delta=" + str(delta_rtp_us) + " (total range=" + str(lastrtpts[key]["min"]) + "-" + str(lastrtpts[key]["max"]) + "). Time period (sec)=",rtp_timeperiod_sec,"AVG=",rtp_avg)

    if (key not in lastseq):
        lastseq[key] = rtp_seq-1
        True;

    if (key not in lastts):
        lastts[key] = 0
        True;

    if (key not in tsdiffcount):
        tsdiffcount[key] = {}
        True;

    tsdiff = rtp_ts - lastts[key]
    delta = rtp_seq - lastseq[key]

    if (delta == 1 or delta == -65535):
        # OK
        #print(key,"ts",bytes2hex(data[4:8]),"decode=",rtp_ts)
        #print(key + " num:" + str(rtp_seq) + ": tsdiff:" + str(tsdiff) + ": OK")
        if (tsdiff < 0):
            WARNING(key + " RTP sequence num:" + str(rtp_seq) + ": timestamp goes backwards:" + str(tsdiff) + f" to {rtp_ts}")
        else:
            DEBUG(key + " RTP sequence num:" + str(rtp_seq) + ": timestamp goes forward:" + str(tsdiff) + f" to {rtp_ts}")
        if (lastts[key] > 0):
            if (tsdiff not in tsdiffcount[key]):
                tsdiffcount[key][tsdiff] = 0
            tsdiffcount[key][tsdiff] += 1
        True;
    else:
        svcstring = ""
        streamname = getStreamName(key)
        ERROR(key + " RTP ERROR in " + key + "(" + streamname + ") error jump of " + str(delta) + " from " + str(lastseq[key]) + " to " + str(rtp_seq))
        True;
    lastseq[key] = rtp_seq
    lastts[key] = rtp_ts

def binp(num, padto=0):
    binary = str(bin(num))[2:]
    while (len(binary) < padto):
        binary = "0" + str(binary)
    return binary
    

def processAdaptationField(key, pidnum, isonum, rtpheader, data):
    global lastpcrrtp
    global lastpcrbase
    global lastpcrext
    global pcrdiffcount
    if (len(data) != 188):
#        print(timestamp, str(key),"NOT VALID PAF decode",rtpheader,data)
        ## Not valid packet
        return None;

    rtp_seq = 1000;
    if (rtpheader != "==FAKE RTP=="):
        rtp_seq = getBigint(rtpheader[2:4])

    flen = data[4]
    if (flen == 0):
        # nothing to parse
#        print(timestamp, str(key) + ";" + str(rtp_seq) + "." + str(isonum), pidnum, " SKIP PAF decode as length 0",bytes2hex(data))
        return None
    flags = data[5]
    pcr_flag = flags & 0x10
    opcr_flag = flags & 0x08
    
    if (pcr_flag):
        # PCR flag is the next 48 bits
        pcr_data = data[6:12]
        pcr_base = getBigint(pcr_data) >> 15
        pcr_ext = (getBigint(pcr_data) & 0x0000000001ff)
#        print("PCR field", binp(getBigint(pcr_data), 48))
#        print("PCR base ", binp(pcr_base, 33))
#        print("PCR ext                                         ", binp(pcr_ext, 9))

        # PCR_base(i) == ((system_clock_frequency * t(i)) DIV 300) % 2^33
        # PCR_ext(i)  == ((system_clock_frequency * t(i)) DIV 1) % 300
        rtp_ts = 1000
        if (rtpheader != "==FAKE RTP=="):
            rtp_ts = getBigint(rtpheader[4:8])
#        print("RTPH: ",bytes2hex(rtpheader,8))
#        print("RTPH: ",bytes2hex(rtpheader[4:8],8))
#        print("RTP:       ",binp(rtp_ts,32),rtp_ts)
#        print("PKT: ",bytes2hex(data))
#        print("PCRdata: ",bytes2hex(pcr_data))
#        print("PCR: ",bin(pcr_base),pcr_base,pcr_ext)
        if (key in lastpcrrtp):
            if (pidnum in lastpcrrtp[key]):
                rtp_diff = rtp_ts - lastpcrrtp[key][pidnum]
                base_diff = pcr_base - lastpcrbase[key][pidnum]
                ext_diff = pcr_ext - lastpcrext[key][pidnum]
#                print(timestamp, str(key) + ";" + str(rtp_seq) + "." + str(isonum), pidnum, "RTPTS=",rtp_ts,"PCR=",pcr_base,", diffs rtpts=",rtp_diff,"pcrdiff=",base_diff,ext_diff % 300)
                if (key not in pcrdiffcount):
                    pcrdiffcount[key] = {}
                if (pidnum not in pcrdiffcount[key]):
                    pcrdiffcount[key][pidnum] = {}
                if (base_diff not in pcrdiffcount[key][pidnum]):
                    pcrdiffcount[key][pidnum][base_diff] = 0

#                print("Store PCR diff of " + str(base_diff) + " for key " + str(key) + ", pid " + str(pidnum))
                pcrdiffcount[key][pidnum][base_diff] += 1
        else:
            lastpcrrtp[key] = {}
            lastpcrbase[key] = {}
            lastpcrext[key] = {}

        lastpcrbase[key][pidnum] = pcr_base
        lastpcrrtp[key][pidnum] = rtp_ts
        lastpcrext[key][pidnum] = pcr_ext
    else:
        True
        # Not PCR flag
#        print(timestamp, str(key) + ";" + str(rtp_seq) + "." + str(isonum), pidnum, " PCR flag",pcr_flag,bytes2hex(data))

def parseSDT(stream, data):
    global svctable
    sdt_data=data[5:]
#    print(timestamp,stream,"Service Description Table",bytes2hex(sdt_data))
    # 0 - table id
    # 1-2 flags
    # 3-4 tsid // network id
    # 5 flags
    # 6 sec num
    # 7 last sec num
    # 8-9 orig net id (reserved for future use + length in spec)
    # 10 reserved
    # 11-12 serviceid
    # 13-15 flags (12 bit)+looplen (12 bit)
    # 16 descriptor (this may be in loops etc)
    if (sdt_data[0] != 0x42):
        WARNING(stream+"WARNING: SDT for non current network, ignoring");
        return;

    ts_id = getBigint(sdt_data[3:5])
    descriptlen = getBigint(sdt_data[14:16]) & 0xfff
    descript_data = sdt_data[16:descriptlen+16]
#    print("SDT",ts_id,descriptlen,"data=",bytes2hex(descript_data))

    # descriptor
    # 0 - 0x48
    # 1 - length
    # 2 - type (0x19)
    # 3 - length of name
    # 4-len+4 - provider name
    # service name len
    # service name
    if (descript_data[0] != 0x48):
        WARNING(stream,"WARNING: SDT Descript not starting with 0x48");
        return
    prov_len = descript_data[3] 
    if (prov_len < 1):
        providerb = bytes("", 'utf-8')
    else:
        providerb = descript_data[4:4+prov_len] 

    svc_len = descript_data[4+prov_len]
    if (svc_len < 1):
        serviceb = bytes("", 'utf-8')
    else:
        serviceb = descript_data[5+prov_len:5+prov_len+svc_len] 

    provider = providerb.decode()
    service = serviceb.decode()

#    print("Service",provider,service)
    if (stream not in svctable["Service"]):
        svctable["Service"][stream] = {}
        svctable["Service"][stream]["name"] = ""
    if (stream not in svctable["Provider"]):
        svctable["Provider"][stream] = {}
        svctable["Provider"][stream]["name"] = ""

    svctable["Service"][stream]["name"] = service
    svctable["Provider"][stream]["name"] = provider
    

def parsePAT(stream, data):
    # assumes 1 program
    # Set aside the mpeg header. First 4 is header, 5 is a pointer (?)
    pat_data = data[5:]
    #print(stream,"PAT",bytes2hex(pat_data),timestamp)
    # format
    # b0     = tableid = 0x00 for a Prog assoc table
    # b1-2   = flags + length
    # b3-4   = tsid
    # b5     = flags
    # b6     = sec num
    # b7     = last sec num
    # b9     = prog number
    # b10-11 = 111(pmap pid)
    # b11-14 =  crc

    prog_num = pat_data[9]
    # 0 is network pid and set by thigns like OBEs
    # 1 is common too and set by things like Appear

    if (stream in current_pat):
        if (pat_data != current_pat[stream]["pat_data"]):
            True
#            print(timestamp,stream, "PAT CHANGE from",bytes2hex(current_pat[stream]["pat_data"]))
#            print(timestamp,stream, "PAT CHANGE   to",bytes2hex(pat_data))
    else:
        current_pat[stream] = {}
        current_pat[stream]["pat_data"] = pat_data
        current_pat[stream]["pmpid"] = 0
#        print(stream, "First PAT found",bytes2hex(pat_data))

    current_pat[stream]["pat_data"] = pat_data

    pmpid = getBigint(pat_data[10:12]) & 0xe0 # mask first 3 bits
#    print(timestamp,stream,"ProgID",prog_num,"PMAPID", pmpid, bytes2hex(pat_data[10:12]))
    current_pat[stream]["pmpid"] = pmpid
        

def parseTS(key,isonum,rtpheader,data):
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

#        print(timestamp,"hdr",hex(hdr[0]),bin(hdr[1]),bin(hdr[2]),bin(hdr[3]), bytes2hex(hdr))
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
        if (adapt == 3):
            processAdaptationField(key, pidnum, isonum, rtpheader, data)

#        if (seqnum >= 5662 and seqnum <= 5662):
#            print("RTP ",seqnum,pidnum,"adapt=",adapt,"hdr=",bytes2hex(hdr))

        if (pidnum not in pidcount[key]):
            pidcount[key][pidnum] = 0

        if (pidnum == 8191):
#            print(key, timestamp, seqnum, "NULL PACKET")
            pidcount[key][pidnum] += 1
            return

        # SDT - service name etc
        if (pidnum == 0x11):
            parseSDT(key,data)

#        print(timestamp,"CONT",bytes2hex(data))
        if (pidnum == 0):
#            print("PAT in", key, pidnum, getBigint(rtpheader[2:4]))
            # TODO -- parse this then set the PAT for the stream
            # Do we need to do more than one program? probably not
            parsePAT(key, data)

        if (pidnum not in lastcc[key]):
            lastcc[key][pidnum] = -1

        #print(key, "STRT parse of PID",pidnum,"cc=",cc,"last=",lastcc[key][pidnum],"rtp=",str(seqnum));
        if (lastcc[key][pidnum] < 0):
            # start of CC
            True;
        else:
            diff = cc - lastcc[key][pidnum]
#            print(key, "COMPARE",cc,lastcc[key][pidnum],diff);
            if (diff == -15):
                diff = 1;
    
        if (diff != 1):
            streamname = getStreamName(key)
            ERROR(key  +" CC ERROR in " + key + " (" + streamname + ") RTP=" + str(seqnum) + "." + str(pidnum) + ". Jumped " + str(diff) + " from " + str(lastcc[key][pidnum]) + " to " + str(cc));

#        print(key,"PID ",pidnum,"=",hex(pidnum),"CC=",cc,"diff=",diff,"lastcc=",lastcc[key][pidnum])
        lastcc[key][pidnum] = cc
        pidcount[key][pidnum] += 1
#        print(key, "FINISHED parse of PID",pidnum,"cc=",cc,"last=",lastcc[key][pidnum]);
    else:
        WARNING("SYNC BYTE INVALID")

def byte2ip(i):
    #return(str(i[2]) + "." + str(i[3]) + "." + str(i[0]) + "." + str(i[1]));
    return(str(i[0]) + "." + str(i[1]) + "." + str(i[2]) + "." + str(i[3]));

def printStatsAndReset(number, realtime):
    global pidcount, tsdiffcount, pcrdiffcount, lastpcrrtp, lastpcrbase, lastpcrext
    number = str(number)

    # If realtime is sent, print 100 blank lines to make it easier to watch in a real time window
    if (realtime):
        for i in range(100):
            STATS("")
    STATS("== CURRENT STATS " + timestamp + " of last " + number + " packets ==")
    for stream in sorted(pidcount):
        tsout = ""
        total = 0
        num = 0
        mn = 99999
        mx = 0
        for tsdiff in sorted(tsdiffcount[stream]):
            tsout += " "+str(tsdiff)+"="+str(tsdiffcount[stream][tsdiff])
            total += tsdiff * tsdiffcount[stream][tsdiff]
            num += tsdiffcount[stream][tsdiff]
            if (tsdiff < mn):
                mn = tsdiff
            if (tsdiff > mx):
                mx = tsdiff

        if (num > 0):
            avg = total / num
            tsout = "avg=" + str(int(avg*100)/100) + ", range=" + str(mn) + "-" + str(mx) + "{" + tsout + "}"
        else:
            True

        streamname = getStreamName(stream)

        rtp_str = ""
#        rtp_str += "min=" + str(lastrtpts[stream]["min"]) + " "

#        print("DBG: ",lastrtpts)
#        print("DBG: ",lastrtpts[stream])
        rtp_avg = (lastrtpts[stream]["last"]-lastrtpts[stream]["start"])/lastrtpts[stream]["num"]
        rtp_str += " max=" + str(int(lastrtpts[stream]["max"]/100)/10) + "ms"
        rtp_str += " avg=" + str(int(rtp_avg/10)/100) + "ms"

        if (stream.startswith("UDP")):
            STATS("Stream: "+stream+" "+streamname+" is a UDP only stream")
        else:
            STATS("Stream: "+stream+" "+streamname+" RTP Packets:"+rtp_str+" Timestamp DIFF " + tsout)

        for pid in sorted(pidcount[stream]):
            pcrtxt = ""
            pid_str=str(pid)
            if (pid == 8191):
                pid_str = "8191 (NULL)"

            if stream in pcrdiffcount:
                if pid in pcrdiffcount[stream]:
                    mnVal = 9999999999999999
                    mxVal = 0
                    numVal = 0
                    totVal = 0
                    valOut = ""
#                    print("DBG",pid_str,pcrdiffcount[stream][pid])
                    for pcrdiff in sorted(pcrdiffcount[stream][pid]):
                        numOfDiff = pcrdiffcount[stream][pid][pcrdiff]
                        totVal += pcrdiff
                        numVal += 1
                        if (pcrdiff < mnVal):
                            mnVal = pcrdiff
                        if (pcrdiff > mxVal):
                            mxVal = pcrdiff
                        valOut += " "+str(pcrdiff)+"="+str(numOfDiff)
                    avgVal = totVal / numVal
                    pcrtxt = " *PCR avg=" + str(int(avgVal*100)/100) + ", range=" + str(mnVal) + "-" + str(mxVal) + " {" + valOut + " }"

            STATS("Stream:"+stream+" " + streamname + " Pid:"+pid_str+" Count:"+str(pidcount[stream][pid])+" " + pcrtxt)
    # end of for each pidcount
    pidcount = {}
    tsdiffcount = {}
    lastpcrrtp = {}
    lastpcrbase = {}
    lastpcrext = {}
    pcrdiffcount = {}

    for stream in lastrtpts:
        lastrtpts[stream]["min"] = 999999999999
        lastrtpts[stream]["max"] = 0
        lastrtpts[stream]["num"] = 0
        lastrtpts[stream]["start"] = -1

def parseEther(eth_pkt, baseFilename, mediumType):
    global lastseq
    global lastts
    global lastrtpts
    global tsdiffcount

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
#        print("ethertype",hex(eth_type[0]),hex(eth_type[1]));
        if (eth_type == b'\x81\x00'):
            vlan_num=getBigint(eth_pkt[14:16])
            ipStart = 18
        elif (eth_type == b'\x08\x00'):
            # Normal ethernet
            ipStart = 14
        elif (eth_type == b'\x88\xcc'):
            # lldp
            return True;
        else:
#            print("UNKNOWN ethertype",hex(eth_type[0]),hex(eth_type[1]));
            return True;
    elif (mediumType == 113):
        # Linux cooked capture (-i any etc)
        ipStart = 18
        eth_type = eth_pkt[14:16]
#        print("ET",bytes2hex(eth_type))
        if (eth_type == b'\x81\x00'):
            vlan_num=getBigint(eth_pkt[16:18])
            ipStart = 20
        elif (eth_type == b'\x08\x00'):
            # Normal ethernet
            ipStart = 16
        elif (eth_type == b'\x88\xcc'):
            # lldp
            return True;
        else:
#            print("UNKNOWN ethertype",hex(eth_type[0]),hex(eth_type[1]));
            return True;
    else:
#        print("UNKNOWN capture type",mediumType)
        return False;

    # Normal capture
    ip_pkt = eth_pkt[ipStart:]

#    print(timestamp,"Got IP packet of len",len(ip_pkt),bytes2hexstream(ip_pkt))
    ip_hdr = ip_pkt[0:20]
    udp_pkt = ip_pkt[20:]

    srcip = byte2ip(ip_hdr[12:16])
    dstip = byte2ip(ip_hdr[16:20])

    srcport = getBigint(udp_pkt[0:2])
    dstport = getBigint(udp_pkt[2:4])
    udplen = getBigint(udp_pkt[4:6])

    data = udp_pkt[8:]
    #print("Got IP packet ",srcip,srcport,dstip,dstport,len(data));
    if ((udplen - 8) == len(data) and (udplen == 1336 or udplen == 1148)):
        # OK, looks like this is the RTP payload
        ts_data = data[12:]
        stream_key = srcip + ":" + str(srcport) + ">" + dstip + ":" + str(dstport);
        parseRTP(stream_key, data)
        numTS = 7
        if (udplen == 1148):
            numTS = 6
        # 7 TS entries
        #print("START PARSE OF ",stream_key)
        for i in range(numTS):
            base = i * 188
            parseTS(stream_key,i,data[0:12],ts_data[base:base+188])

        # Save to TS
        if (baseFilename == None):
            True;
        else:
            ofname = baseFilename + "." + srcip + "." + str(srcport) + "_" + dstip + "." + str(dstport)  + ".ts";
#        print("Writing to ", ofname)
            oh = open(ofname,"ab");
            oh.write(ts_data);
            oh.close()
    elif ((udplen - 8) == len(data) and udplen == 1324):
#        print("UDP not RTP packet")
        fakertp = "==FAKE RTP=="
        ts_data = data
        stream_key = "UDP:" + srcip + ":" + str(srcport) + ">" + dstip + ":" + str(dstport);
        lastseq[stream_key] = 1111
        lastrtpts[stream_key] = {}
        lastrtpts[stream_key]["min"] = 999999999999
        lastrtpts[stream_key]["max"] = 1
        lastrtpts[stream_key]["num"] = 1
        lastrtpts[stream_key]["start"] = -1
        lastrtpts[stream_key]["last"] = 1
        tsdiffcount[stream_key] = {}
        for i in range(7):
            base = i * 188
            parseTS(stream_key,i,fakertp,ts_data[base:base+188])
    else:
        True;
        # Not an RTP packet with 7x188 byte TS
#        print("ERROR in packet ",srcip,srcport,dstip,dstport,"act len=",len(data),"claimed len",udplen)
    return True
    

def readPacket(fh, baseFilename, mediumType):
    global timestamp,starttime,unix_time,unix_time_high,rtp_us
    header = bytearray(fh.read(16))
#    print("READ PACKET, bytes=",len(header))
    unix_time = getint(header[0:4])
    unix_time_high = getint(header[4:8])
    rtp_us = int(str(unix_time))*1000*1000
    rtp_us += int(str(unix_time_high).zfill(6))

    timestamp = datetime.utcfromtimestamp(unix_time).strftime('%Y-%m-%d %H:%M:%S') + "." + str(getint(header[4:8])).zfill(6)

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

def run(capfile, destfile, realtime):
    global last_stat_print
    fh = sys.stdin.buffer
    if (capfile == None):
        INFO("Read from STDIN");
        capfile = "STDIN"
    else:
        INFO("Read from "+capfile);
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
#            print("DBG Packet Number", num)
            #if (statsEvery > 0 and num % statsEvery == 0):
            if (last_stat_print == 0):
                last_stat_print = rtp_us

            if (statsEvery > 0 and (rtp_us-last_stat_print > statsEvery * 1000000)):
                last_stat_print = rtp_us
                printStatsAndReset(num, realtime)
                num = 0
            True;
        INFO("Parse of " + capfile + " from " + starttime + " complete. "+str(num) + " packets read")
        printStatsAndReset(num, realtime)
        if (destfile != None):
            INFO("TS dumped to "+destfile+".*.ts")

# sudo tcpdump -i ens1f1 udp port 6204 or port 6205 or port 6206 -w - | ./dumpts.py -s 20000
# ./dumpts.py -i cap.cap
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--in-file', help="File to read from (none=stdin)")
    parser.add_argument('-o', '--out-file', help="Root of file to write to (none=dontwrite)")
    parser.add_argument('-s', '--stats-every', type=int, help="Show and reset stats every n seconds", default=0)
    parser.add_argument('-rt', '--real-time', action="store_true", help="Clear the screen before printing stags for easy real time use")
    parser.add_argument('-l', '--log-file', help="Output to different log files (logfile.debug.log, logfile.stats.log, logfile.errors.log) instead of STDOUT", default="")
    args = parser.parse_args()
    statsEvery = args.stats_every
    log_base = args.log_file
    run(args.in_file, args.out_file, args.real_time)
    
