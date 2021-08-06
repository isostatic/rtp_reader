#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/ip.h>
#include <linux/udp.h>
        
const u64 STREAM_SAMPLE_RESET_TIME_NS = 5000000000; // time to reset stream counters in nanoseconds - 5 seconds
const u64 BYTES_PER_IP_PACKET = 1328 + sizeof(struct udphdr) + sizeof(struct iphdr); // rtp = 7*188 + 12 = 1328
const u64 MAX_SDT_TIME_NS = 30000000000; // 30 second max SDT age before we expire it

const int MAX_PROV_LEN = 30; // maximum length of provider/service strings we want to cope with

// Enough data to uniquely identify a stream
struct StreamID {
    u16 srcport;
    u16 dstport;
    u32 srcip;
    u32 dstip;
};

// Database of information on the streams we can see
struct StreamInfo {
    u64 lastPacketTime;
    u64 firstPacketTime;
    u64 packetnum;
    u16 lastSeqNum;
    u64 errors; // u64 - lets hope not!!
    char serviceName[MAX_PROV_LEN+1];
    char providerName[MAX_PROV_LEN+1];
    u64 lastSeenSDT;
};

// RTP header
struct rtphdr {
    u8 flags1;
    u8 flags2;
    u16 seq;
    u32 ts;
    u32 ssrc;
};
// MPEGTS header, there's 7 of them in the RTP streams we like
struct mpeghdr {
    // 4 byte header
    u8 sync;
    u8 flagpidh;
    u8 pidl;
    u8 flagcc;
    // Rest of it
    u8 rest[184];
};


// bpf_hash (name, key, val)
BPF_HASH(last, struct StreamID, struct StreamInfo);

int rtpwatch(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data; // Pointer to start of the packet
    void *data_end = (void *)(long)ctx->data_end; // Pointer to end of the packet
    
    unsigned int i; // for iterating over mpegts packets
    unsigned int seqnum; // RTP sequence number
    u64 arrivalts = bpf_ktime_get_ns(); // Time the kernel had the packet arriving at - in nanoseconds since boot I think
    struct StreamID key = {}; // Information to identify a unique stream
    struct StreamInfo *info_p; // Hash to store information about a unique stream

    s64 deltaTimeStamp = 0; // nanoseconds since the previous RTP packet for this stream
    u64 deltaAgeOfStream = 0; // nanoseconds since first seeing the stream (or resetting the statistics)
    u64 deltaSDT = 0; // nanoseconds since last saw an SDT -- if we don't see it for too long we wipe historical data
    signed int deltaSeqNum = 0; // the change in sequence number since the last packet. Chagne of 1 is good, change of -65535 is good (rollover). Change of zero is a duplicate. Negative change is sign of a reorder, change > 1 can be sign of loss (or reorder)
    
    // First up we are only interested in specific IPv4/UDP/RTP packets with 7TS packets contained within
    unsigned int pkt_len = data_end - (void*)data;
    if (pkt_len != 1370) { return XDP_PASS; }

    // Bound checking of different headers to ensure code compiles by ebpf, fail if the packet is too short
    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) > data_end) { return XDP_PASS; }
    struct iphdr *ip = (void*)eth + sizeof(*eth);
    if ((void*)ip + sizeof(*ip) > data_end) { return XDP_PASS; }
    struct udphdr *udp = (void*)ip + sizeof(*ip);
    if ((void*)udp + sizeof(*udp) > data_end) { return XDP_PASS; }
    struct rtphdr *rtp = (void*)udp + sizeof(*udp);
    if ((void*)rtp + sizeof(*rtp) > data_end) { return XDP_PASS; }

    // RTP type (bit 9-15) should be 0x21 // 33 otherwise fail fast
    if ((rtp->flags2 & 0x7f) != 33) {
        bpf_trace_printk("RTP not mpeg2 transprot stream");
        return XDP_PASS;
    }

    // OK it's a valid RTP stream, we're set, generate the unique key identifying this stream
    key.srcip = ip->saddr;
    key.dstip = ip->daddr;
    key.srcport = ntohs(udp->source);
    key.dstport = ntohs(udp->dest);

    // Pull the current stream info database to update from the SDT
    struct StreamInfo template_info = {0};
    info_p = last.lookup_or_init(&key, &template_info);
    
    // Check the contents of the mpegts packets and look for the SDT. SDT is only shown periodically (sometimes 10 times a second, sometimes once every 10 seconds)
    // Iterate over all 7 mpegts packets, check they are valid mpegts (start with 0x47)
    struct mpeghdr *mpeg[7];
    for (i = 0; i < 7; i++) {

        mpeg[i] = (void*)rtp + sizeof(*rtp) + (188*i); // we can work with mpeg[i] as a struct representing the mpegts packet
        if ((void*)mpeg[i] + sizeof(*mpeg[i]) > data_end) { return XDP_PASS; } // bound checking

        if (mpeg[i]->sync != 0x47) {
            bpf_trace_printk("MPEG packet %lu sync byte not 0x47 (is 0x%x)\n", i, mpeg[i]->sync);
            return XDP_PASS;
        }

        unsigned short pidH = mpeg[i]->flagpidh & 0x1F; // first 3 bits aren't part of the  pid number
        unsigned short pidL = mpeg[i]->pidl;
        unsigned pid = (pidH <<8) + pidL;

        // We care about the SDT pid (0x11), but not other ones (like null frames (0x1FFF))
        if (pid == 0x11) {
            /* SDT structure
             * 0 = pointer (zero)
             * 1 = table number
             * 2-3 == flags + len
             * 4-5 == tsid
             * 6 = flags
             * 7 = section number
             * 8 = lastsection number
             * 9-10 = original network id -- reserver
             * 11 = reserved
             * 12-13 = svcid
             * 14-16 flags + descriptor loop length
             * 17 descriptor flag of 0x48
             * 18 descriptor length
             * 20 = provider len
             * 21---- (provider)(svclen)(service), providerlen + svclen could be zero, or more. 

             Technically there's more things in the descriptors (including multiple ones, pointers to other locations etc) but not for the RTP streams we're insteresting
             */

            info_p->lastSeenSDT = arrivalts;

            unsigned short provstart = 21;
            unsigned short svclenoffset = 21;
            u8 provlen = mpeg[i]->rest[20];

            // Iterate over the next bytes and copy into the provider and service name char array
            if (provlen <= MAX_PROV_LEN) {
                // OK this is safe, we can cope
                int p = 0;
                for (p = 0; p < MAX_PROV_LEN; p++) {
                    if (p >= provlen) {
                        info_p->providerName[p] = '\0';
                    } else {
                        info_p->providerName[p] = mpeg[i]->rest[provstart + p];
                        svclenoffset++;
                    }
                }
                u8 svclen = mpeg[i]->rest[svclenoffset];
                // same for service length
                if (svclen <= MAX_PROV_LEN) {
                    for (p = 0; p < MAX_PROV_LEN; p++) {
                        if (p >= svclen) {
                            info_p->serviceName[p] = '\0';
                        } else {
                            info_p->serviceName[p] = mpeg[i]->rest[svclenoffset + 1 + p];
                        }
                    }
                }
            }
        } // end of SDT handling
    } // end of mpeg processing

    // Calculate useful data on this RTP packet compared with previous ones
    seqnum = ntohs(rtp->seq);
    deltaTimeStamp = arrivalts - info_p->lastPacketTime;
    deltaSeqNum = seqnum - info_p->lastSeqNum;
    deltaAgeOfStream = arrivalts - info_p->firstPacketTime;
    deltaSDT = arrivalts - info_p->lastSeenSDT;

    if (seqnum % 5000 == 0) {
        // dump out statistics for debugging
        bpf_trace_printk("------------------------- CURRENT STATS ------------------------\n");
        bpf_trace_printk("Valid MPEGRT/RTP sport %lu packet seq %lu delta=%d\n", key.srcport, seqnum, deltaSeqNum);
        bpf_trace_printk("Valid MPEGRT/RTP sport %lu current packet time %llu delta=%lld\n", key.srcport, arrivalts, deltaTimeStamp);
        bpf_trace_printk("Valid MPEGRT/RTP sport %lu start time %llu time since reset=%lld\n", key.srcport, info_p->firstPacketTime, deltaAgeOfStream);
        bpf_trace_printk("Valid MPEGRT/RTP sport %lu seen %llu packets since reset\n", key.srcport, info_p->packetnum);
        bpf_trace_printk("Valid MPEGRT/RTP sport last seen provider name >%s<\n", info_p->providerName, info_p->serviceName);
        bpf_trace_printk("Valid MPEGRT/RTP sport last seen service name >%s<\n", info_p->serviceName, info_p->serviceName);
        bpf_trace_printk("Valid MPEGRT/RTP sport last seen SDT change >%lu<\n", deltaSDT);
        bpf_trace_printk("----------------------- END CURRENT STATS ----------------------\n");
    }

    if (deltaSeqNum == 1) {
        // Normal incrementing, nothing to do
    } else if (deltaSeqNum == -65535) {
        // Normal rollover, nothing to do
        bpf_trace_printk("RTP rollover seq %lu delta=%d\n", seqnum, deltaSeqNum);
    } else {
        bpf_trace_printk("RTP packet loss %s seq %lu delta=%d\n", info_p->serviceName, seqnum, deltaSeqNum);
        info_p->errors++;
    }

    if (deltaAgeOfStream > STREAM_SAMPLE_RESET_TIME_NS) {
        long long packetRateAdj = info_p->packetnum * 1000000000;
        long long current_packet_rate = packetRateAdj / deltaAgeOfStream;
        long long ip_rate = BYTES_PER_IP_PACKET * current_packet_rate * 8;

        bpf_trace_printk("Reset stream data for source %s, %llu errors, stream %llubps\n", info_p->serviceName, info_p->errors, ip_rate);
        info_p->packetnum = 0;
        info_p->lastSeqNum = 0;
        info_p->lastPacketTime = 0;
        info_p->firstPacketTime = 0;
        info_p->errors = 0;
        // Only expire really old SDT data
        if (deltaSDT > MAX_SDT_TIME_NS) {
            bpf_trace_printk("Reset expired SDT data too\n");
            info_p->serviceName[0] = '-'; info_p->serviceName[1] = '\0';
            info_p->providerName[0] = '-'; info_p->providerName[1] = '\0';
        }
    }

    // Store data about this packet for future use
    if (info_p->firstPacketTime == 0) {
        info_p->firstPacketTime = arrivalts;
    }
    info_p->lastPacketTime = arrivalts;
    info_p->lastSeqNum = seqnum;
    info_p->packetnum++;

    return XDP_PASS;
}


