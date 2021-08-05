#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/ip.h>
#include <linux/udp.h>
        
const u64 STREAM_SAMPLE_RESET_TIME_NS = 5000000000; // time to reset stream counters in nanoseconds - 5 seconds
const u64 BYTES_PER_IP_PACKET = 1328 + sizeof(struct udphdr) + sizeof(struct iphdr); // rtp = 7*188 + 12 = 1328
const u64 MAX_SDT_TIME_NS = 30000000000; // 30 second max SDT age before we expire it

const int MAX_PROV_LEN = 30; // maximum length of provider/service strings

struct StreamID {
    // struct to store
    u16 srcport;
    u16 dstport;
    u32 srcip;
    u32 dstip;
};

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


// bpf_hash (name, key, val)
BPF_HASH(last, struct StreamID, struct StreamInfo);
//BPF_HASH(lastpkt, struct streamdata *);

int rtpwatch(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    
    unsigned int i;
    unsigned int n;
    unsigned int payload_size;
    unsigned char *payload;
    unsigned int seqnum;
    u64 arrivalts = bpf_ktime_get_ns();
    // hash storing
    struct StreamID key = {};
    struct StreamInfo *info_p;
    s64 deltaTimeStamp = 0;
    u64 deltaAgeOfStream = 0;
    u64 deltaSDT = 0;
    signed int deltaSeqNum = 0;

    if ((void*)eth + sizeof(*eth) <= data_end) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void*)ip + sizeof(*ip) <= data_end) {
            if (ip->protocol == IPPROTO_UDP) {
                struct udphdr *udp = (void*)ip + sizeof(*ip);
                // Esnure packet is 1328 bytes long
                if ((void*)udp + sizeof(*udp) + 1328 <= data_end) {
                    payload_size = ntohs(udp->len) - sizeof(struct udphdr);
                    if (payload_size == 1328) {
                        // could be RTP
                        payload = (void*)udp + sizeof(*udp);
                        // check RTP type is 33 
                        if ((payload[1] & 0x7f) != 33) {
                            bpf_trace_printk("NOT RTP packet %lu\n", payload[1]);
                            return XDP_PASS;
                        }

                        // Pull the current stream info database
                        struct StreamInfo template_info = {0};
                        info_p = last.lookup_or_init(&key, &template_info);

                        // check MPEG sync every 188 bytes from 12 through 1140, check 0x47 (71)
                        // keep an eye for PID of 0x11 which is the Service DecsriptionTable 
                        for (i = 12; i <= 1140; i = i + 188) {
                            if (payload[i] != 71) {
                                bpf_trace_printk("NOT MPEG packet %lu = %lu\n", i, payload[i]);
                                return XDP_PASS;
                            }
                            unsigned short pidH = payload[i+1] & 0x1F; // first 3 bits aren't the pid number
                            unsigned short pidL = payload[i+2];
                            unsigned pid = (pidH <<8) + pidL;
                            if (pid == 8191) {
                                // null mpeg frame, ignore
                            } else if (pid == 0x11) {
                                // SDT data
                                /* i+0 = syncbyte, +1+2 = pid, +3=adaption field, contc etc
                                 * +4 == tablenum
                                 * +5-6 == flags
                                 * +7-8 tsid
                                 * +9 flags
                                 * +10 sect num
                                 * +11 lastsecnum
                                 * +12-13 orignetid // resever
                                 * +14 res
                                 * +15-16 svcid
                                 * +17-19 flags
                                 * +21 descriptor
                                */
                                /* Descriptior
                                 21 - 0x48
                                 22 - length
                                 23 - svctype
                                 24 - prov namelength
                                */
                                if (payload[i+21] == 0x48) {
                                    info_p->lastSeenSDT = arrivalts;
                                    unsigned short provlen = payload[i+24];
                                    if (provlen <= MAX_PROV_LEN) {
                                        unsigned short provstart = i+25;
                                        unsigned short svclenoffset = i+25;
                                        int p = 0;
                                        for (p = 0; p < MAX_PROV_LEN; p++) {
                                            if (p >= provlen) {
                                                info_p->providerName[p] = '\0';
                                            } else {
                                                info_p->providerName[p] = payload[provstart + p];
                                                svclenoffset++;
                                            }
                                        }
                                        info_p->providerName[MAX_PROV_LEN] = '\0';
                                        unsigned short svclen = payload[svclenoffset];
                                        if (svclen <= MAX_PROV_LEN) {
                                            unsigned short svcstart = svclenoffset + 1;
                                            for (p = 0; p < MAX_PROV_LEN; p++) {
                                                if (p >= svclen) {
                                                    info_p->serviceName[p] = '\0';
                                                } else {
                                                    info_p->serviceName[p] = payload[svcstart + p];
                                                }
                                            }
                                            info_p->serviceName[MAX_PROV_LEN] = '\0';
                                        } else {
                                            bpf_trace_printk("Service length too long (%lu)\n", svclen);
                                        }
                                    } else {
                                        bpf_trace_printk("Provider length too long (%lu)\n", provlen);
                                    }
//                                    bpf_trace_printk("Provider >%s<\n", info_p->providerName);
//                                    bpf_trace_printk("Service >%s<\n", info_p->serviceName);
                                }
                            } else {
                                // normal mpeg content
//                                bpf_trace_printk("Packet has PID %x in it at byte %lu\n", pid, i);
                            }
                        }
                        
                        // Find out useful data - RTP sequence number
                        seqnum = (payload[2]<<8) + payload[3];

                        // OK we're set, generate the unique key identifying this stream
                        key.srcip = ip->saddr;
                        key.dstip = ip->daddr;
                        key.srcport = ntohs(udp->source);
                        key.dstport = ntohs(udp->dest);

                        
                        deltaTimeStamp = arrivalts - info_p->lastPacketTime;
                        deltaSeqNum = seqnum - info_p->lastSeqNum;
                        deltaAgeOfStream = arrivalts - info_p->firstPacketTime;
                        deltaSDT = arrivalts - info_p->lastSeenSDT;

                        if (seqnum % 1000 == 0) {
                            // dump out statistics for debugging
/*
                            bpf_trace_printk("Valid MPEGRT/RTP sport %lu packet seq %lu delta=%d\n", key.srcport, seqnum, deltaSeqNum);
                            bpf_trace_printk("Valid MPEGRT/RTP sport %lu current packet time %llu delta=%lld\n", key.srcport, arrivalts, deltaTimeStamp);
                            bpf_trace_printk("Valid MPEGRT/RTP sport %lu start time %llu time since reset=%lld\n", key.srcport, info_p->firstPacketTime, deltaAgeOfStream);
                            bpf_trace_printk("Valid MPEGRT/RTP sport %lu seen %llu packets since reset\n", key.srcport, info_p->packetnum);
                            bpf_trace_printk("Valid MPEGRT/RTP sport last seen provider name >%s<\n", info_p->providerName, info_p->serviceName);
                            bpf_trace_printk("Valid MPEGRT/RTP sport last seen service name >%s<\n", info_p->serviceName, info_p->serviceName);
                            bpf_trace_printk("Valid MPEGRT/RTP sport last seen SDT change >%lu<\n", deltaSDT);
*/
                        }
                        if (deltaSeqNum == 1) {
                            // Normal incrementing, nothing to do
                        } else if (deltaSeqNum == -65535) {
                            // Normal rollover, nothing to do
//                            bpf_trace_printk("RTP rollover seq %lu delta=%d\n", seqnum, deltaSeqNum);
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

                        // Store data about where we are
                        if (info_p->firstPacketTime == 0) {
                            info_p->firstPacketTime = arrivalts;
                        }
                        info_p->lastPacketTime = arrivalts;
                        info_p->lastSeqNum = seqnum;
                        info_p->packetnum++;
                    }
                }
            }
        }
    }
    return XDP_PASS;
}
