from bcc import BPF
from time import sleep
from pathlib import Path
import signal
import socket


bpf = None
class SignalTerminate(Exception):
    pass


# def int_to_ip(int_ip):
#     return socket.inet_ntoa(int_ip.to_bytes(4, 'big'))

def int_to_ip(int_ip):
    return socket.inet_ntop(socket.AF_INET, int_ip.to_bytes(4, 'little'))

def handle_sigterminate(signum, frame):
    raise SignalTerminate("Received SIGTERM Terminating ebpf program...")

def load_bpf_programs(src_path, type):
    print("Loading BPF program of type ::",type)
    bpf_src = Path(src_path).read_text()
    bpf = BPF(text=bpf_src)
    return bpf

def attach_xdp_program(bpf, interface, func_str):
    xdp_function = bpf.load_func(func_str, BPF.XDP)
    bpf.attach_xdp(interface, xdp_function, 0)
    return bpf

def detach_xdp_program(bpf, interface):
    bpf.remove_xdp(interface, 0)

def process_packets(cpu, data, size):
    global bpf
    event = bpf["packet_info"].event(data)
    #print(f"{int_to_ip(event.src_ip)} -> {int_to_ip(event.dst_ip)} : {event.src_port} -> {event.dst_port}")
    print(f"{int_to_ip(event.src_ip)} -> {int_to_ip(event.dst_ip)} : {event.src_port} -> {event.dst_port} : {event.protocol} : {event.len} bytes")


def main():
    signal.signal(signal.SIGTERM, handle_sigterminate)
    
    INTERFACE = "wlp114s0"
    global bpf
    bpf = load_bpf_programs("./NetworkFilter/ebpf_probe.c", "kprobe")
    attach_xdp_program(bpf, INTERFACE, "xdp_packet_filter")
    
    #packet_count_map = bpf.get_table("packet_count_map")

    try:
        print("Prcoessing IP Packets... Hit Ctrl-C to end.")
        bpf["packet_info"].open_perf_buffer(process_packets)
        #print("Counting the packets... Hit Ctrl-C to end.")
        # while True:
        #     sleep(1)
        #     total_packets = 0
        #     for key in packet_count_map.keys():
        #         counter = packet_count_map[key]
        #         if counter:
        #             total_packets += counter.value
        #     packet_per_sec = (total_packets - prev_total_packets);
        #     prev_total_packets = total_packets
        #     print("Total packets: ", total_packets, " Packets per second: ", packet_per_sec)
        while True:
            bpf.perf_buffer_poll()

    except (KeyboardInterrupt,SignalTerminate) as e:
        print(f"{e}. Interrupting eBPF program...")
    finally:
        print("Detaching eBPF program from interface and exiting::",INTERFACE)
        detach_xdp_program(bpf, INTERFACE)

if __name__ == "__main__":
    main()