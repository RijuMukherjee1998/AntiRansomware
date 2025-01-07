from bcc import BPF
from struct import unpack
import socket
import pyroute2

bpf= BPF(src_file="./NetworkFilter/tc_egress.c")

def int_to_ip(int_ip):
    return socket.inet_ntop(socket.AF_INET, int_ip.to_bytes(4, 'little'))

def print_event(cpu, data, size):
    event = bpf["packet_info"].event(data)
    print(f"Protocol: {event.protocol} ::: Source IP: {int_to_ip(event.src_ip)}, Dest IP: {int_to_ip(event.dst_ip)}, Src Port: {event.src_port}, Dst Port: {event.dst_port}, Packet_Killed: {event.packet_killed}")

def create_tc(interface):
    ip = pyroute2.IPRoute()
    ipdb = pyroute2.IPDB(nl=ip)
    try:
        idx = ipdb.interfaces[interface].index
    except:
        print(f"[-] {interface} interface not found")
        return False, False, False

    try:
        # deleting if exists from previous run
        ip.tc("del", "clsact", idx)
    except:
        pass
    ip.tc("add", "clsact", idx)
    return ip, ipdb, idx

interface = "wlp114s0"
ip, ipdb, idx = create_tc(interface)
# loading TC
fn = bpf.load_func("handle_egress", BPF.SCHED_CLS)
ip.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff3", classid=1, direct_action=True)

bpf["packet_info"].open_perf_buffer(print_event)

print("[+] Monitoring started\n")
while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        break

ip.tc("del", "clsact", idx)
ipdb.release()