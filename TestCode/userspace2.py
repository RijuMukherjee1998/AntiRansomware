from bcc import BPF
import socket

# Load the BPF program
bpf_tcp = BPF(src_file="./NetworkFilter/sock.c")

bpf_udp = BPF(src_file="./NetworkFilter/sock.c")

# Attach kprobe to udp_sendmsg and udp_recvmsg
bpf_tcp.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")

bpf_udp.attach_kprobe(event="udp_sendmsg", fn_name="trace_tcp_sendmsg")

def int_to_ip(int_ip):
    return socket.inet_ntop(socket.AF_INET, int_ip.to_bytes(4, 'little'))
# Print UDP connection info
def print_event_tcp(cpu, data, size):
    event = bpf_tcp["packet_info"].event(data)
    print(f"TCP ::: PID: {event.pid}, Source IP: {int_to_ip(event.src_ip)}, Dest IP: {int_to_ip(event.dst_ip)}, Src Port: {event.src_port}, Dst Port: {event.dst_port}")

def print_event_udp(cpu, data, size):
    event = bpf_udp["packet_info"].event(data)
    print(f"UDP ::: PID: {event.pid}, Source IP: {int_to_ip(event.src_ip)}, Dest IP: {int_to_ip(event.dst_ip)}, Src Port: {event.src_port}, Dst Port: {event.dst_port}")
# Open perf buffer and poll for incoming events
bpf_tcp["packet_info"].open_perf_buffer(print_event_tcp)
bpf_udp["packet_info"].open_perf_buffer(print_event_udp)
while True:
    bpf_tcp.perf_buffer_poll()
    bpf_udp.perf_buffer_poll()
