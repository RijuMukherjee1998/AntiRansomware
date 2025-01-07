#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <uapi/linux/ip.h>
#include <bcc/helpers.h>
#include <bcc/proto.h>
#include <linux/pkt_cls.h>

#define BLOCKED_IP_ARRAY_SIZE 10

BPF_PERF_OUTPUT(packet_info);
BPF_HASH(blocked_ip_map, u32, u32);
struct packet_info_t {
    u64 timestamp;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u32 len;
    char protocol;
    char packet_killed;
};

int handle_egress(struct __sk_buff *ctx)
{
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    struct ethhdr *eth = data;
    /* length check */
    if ((void *)(eth + 1) > data_end)
    {
        return TC_ACT_OK;
    }

    if (eth->h_proto != htons(ETH_P_IP))
    {
        return TC_ACT_OK;
    }

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
    {
        return TC_ACT_OK;
    }
    struct packet_info_t pkt_info = {};
    pkt_info.timestamp = bpf_ktime_get_ns();
    pkt_info.src_ip =  ip->saddr;
    pkt_info.dst_ip =  ip->daddr;
    pkt_info.packet_killed = 'F';
    if(ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)((void *)ip + ip->ihl * 4);
        if((void *)(udp + 1) > data_end)
        {
            return TC_ACT_SHOT;
        }

        pkt_info.src_port = ntohs(udp->source);
        pkt_info.dst_port = ntohs(udp->dest);
        pkt_info.len = ntohs(udp->len);
        pkt_info.protocol = 'U';  
    }
    else if (ip->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp = (struct tcphdr *)((void *)ip + ip->ihl * 4);
        if((void *)(tcp + 1) > data_end)
        {
            return TC_ACT_SHOT;
        }
        pkt_info.src_port = ntohs(tcp->source);
        pkt_info.dst_port = ntohs(tcp->dest);
        pkt_info.len = ntohs(tcp->doff * 4);
        pkt_info.protocol = 'T';
    }
    else
        return TC_ACT_OK;
    
    u32 key = pkt_info.dst_ip;
    u32 *value = blocked_ip_map.lookup(&key);
    if(value)
    {
        pkt_info.packet_killed = 'T';
    }
    // if(pkt_info.dst_port == 5000)
    // {
    //     pkt_info.packet_killed = 'T';
    // }
    packet_info.perf_submit(ctx, &pkt_info, sizeof(pkt_info));
    // if(pkt_info.dst_port == 5000)
    // {
    //     return TC_ACT_SHOT;
    // }
    if(pkt_info.packet_killed == 'T')
    {
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}