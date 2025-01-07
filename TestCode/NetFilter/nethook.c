#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

// Inline definition of ntohs for BPF programs
static __inline __u16 ntohs(__u16 x) {
    return __builtin_bswap16(x);
}
int udp_counter = 0;
int tcp_counter = 0;

SEC("xdp")
int udpfilter(struct xdp_md *ctx) 
{ 
    // Print a message when a packet is received
    bpf_printk("got a packet\n"); 

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

    // Check if the packet is UDP
    if (ip->protocol == IPPROTO_UDP ) 
    {

        // Parse UDP header
        struct udphdr *udp = (struct udphdr *)((void *)ip + ip->ihl * 4); 
        if ((void *)(udp + 1) > data_end) 
        {
            return XDP_DROP; 
        }    
        udp_counter++;
        // Print the UDP destination port (converted from network to host order)
        bpf_printk("UDP source port: %u\n", ntohs(udp->source));
        bpf_printk("UDP destination port: %u\n", ntohs(udp->dest));
        bpf_printk("UDP length: %u\n", ntohs(udp->len));
        bpf_printk("UDP checksum: %u\n", ntohs(udp->check)); 
        // Check destination port
        if (udp->dest == __constant_htons(7999)) 
        {   
            bpf_printk("UDP port 7999\n"); 

            // Change the UDP destination port to 7998 (Redirecting the port 7999 to 7998)
            udp->dest = __constant_htons(7998);  
        }
        bpf_printk("UDP packets checked so far: %d\n", udp_counter);
    }
    if(ip->protocol == IPPROTO_TCP) 
    {
        // Parse TCP header
        struct tcphdr *tcp = (struct tcphdr *)((void *)ip + ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
        {
            return XDP_DROP;
        }

        bpf_printk("TCP source port: %u\n", ntohs(tcp->source));
        bpf_printk("TCP destination port: %u\n", ntohs(tcp->dest));
        bpf_printk("TCP length: %u\n", ntohs(tcp->doff) * 4);
        bpf_printk("TCP checksum: %u\n", ntohs(tcp->check));
        tcp_counter++;
        bpf_printk("TCP packets checked so far: %d\n", tcp_counter);     
    }

    return XDP_PASS; 
}

char _license[] SEC("license") = "GPL";
