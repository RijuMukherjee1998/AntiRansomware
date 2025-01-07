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

BPF_ARRAY(packet_count_map, __u64, 1);
BPF_PERF_OUTPUT(packet_info);

struct packet_info_t {
    u64 timestamp;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u32 len;
    char protocol;
};


// static __inline __u16 ntohs(__u16 x) {
//     return __builtin_bswap16(x);
// }
//
// int xdp_packet_counter(struct xdp_md *ctx) {
//     __u32 key = 0;
//     __u64* counter;

//     counter = packet_count_map.lookup(&key);
//     if(counter == NULL)
//         return XDP_ABORTED;

//     // Increment the counter
//     __sync_fetch_and_add(counter, 1);
//     return XDP_PASS;
// }

int xdp_packet_filter(struct xdp_md *ctx) 
{
    // Access packet data
    void *data = (void *)(long)ctx->data; 
    void *data_end = (void *)(long)ctx->data_end; 

    // Parse Ethernet header
    struct ethhdr *eth = data; 
    if ((void *)(eth + 1) > data_end) 
    { 
        return XDP_PASS; 
    }

    // Check if the packet is IP
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // Parse IP header
    struct iphdr *ip = (struct iphdr *)(eth + 1); 
    if ((void *)(ip + 1) > data_end) 
    { 
        return XDP_PASS; 
    }
    struct packet_info_t p_info = {};
    p_info.timestamp = bpf_ktime_get_ns();
    p_info.src_ip =  ip->saddr;
    p_info.dst_ip =  ip->daddr;
    
    if(ip->protocol == IPPROTO_UDP) {
        // Parse UDP header
        struct udphdr *udp = (struct udphdr *)((void *)ip + ip->ihl * 4); 
        if ((void *)(udp + 1) > data_end) 
        {
            return XDP_DROP; 
        }  
        p_info.protocol = 'U';
        p_info.src_port = ntohs(udp->source);
        p_info.dst_port = ntohs(udp->dest);
        p_info.len = ntohs(udp->len);
    }
    else if(ip->protocol == IPPROTO_TCP) {
        // Parse TCP header
        struct tcphdr *tcp = (struct tcphdr *)((void *)ip + ip->ihl * 4); 
        if ((void *)(tcp + 1) > data_end) 
        {
            return XDP_DROP; 
        }
        p_info.protocol = 'T';
        p_info.src_port = ntohs(tcp->source);
        p_info.dst_port = ntohs(tcp->dest);
        p_info.len = ntohs(tcp->doff) * 4;
    }
    else
        return XDP_PASS;
    packet_info.perf_submit(ctx, &p_info, sizeof(p_info));
    return XDP_PASS;
}