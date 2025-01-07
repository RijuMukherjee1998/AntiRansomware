#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

// Structure to store packet information
struct process_packet_info_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u64 timestamp;
    u32 pkt_len;
};

// Output for sending data to user-space
BPF_PERF_OUTPUT(packet_info);

// Function to read IP addresses and ports from the `sock` structure
int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size)
{
    struct process_packet_info_t p_info = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    // Get the current process ID
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    p_info.pid = pid;
    p_info.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&p_info.comm, sizeof(p_info.comm));
    // Get the timestamp
    p_info.timestamp = bpf_ktime_get_ns();

    // Declare local variables to hold kernel data
    u32 saddr = 0, daddr = 0;
    u16 sport = 0, dport = 0;

    // Read data from `inet_sock` (inet_saddr, inet_daddr, inet_sport, inet_dport)
    bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->sk_rcv_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->sk_daddr);
    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->sk_num);
    
    // The destination port is stored in the `sk_dport` field, part of `inet_sock`
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->sk_dport);

    // Populate the packet info structure
    p_info.src_ip = saddr;
    p_info.dst_ip = daddr;
    p_info.src_port = sport;
    p_info.dst_port = ntohs(dport);
    p_info.pkt_len = size;

    // Submit the event to user-space
    packet_info.perf_submit(ctx, &p_info, sizeof(p_info));
    return 0;
}
