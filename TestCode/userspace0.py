from bcc import BPF
from pathlib import Path


bpf_proc_source = Path("./ProcessFilter/prochook.c").read_text()
bpf_proc = BPF(text=bpf_proc_source)

bpf_net_source = Path("./NetworkFilter/nethook.c").read_text()
bpf_net = BPF(text=bpf_net_source)

# def process_clone_event(cpu, data, size):
#     event = bpf["clone_events"].event(data)
#     print(f"Executable: {event.filename.decode()}. Process {event.comm.decode()} (UID: {event.uid}, PID: {event.pid}, PPID: {event.ppid}) called sys_clone")

def process_clone_event(cpu, data, size):
    event = bpf_proc["clone_events"].event(data)
    print(f"Process {event.comm.decode()} (PID: {event.pid}, PPID: {event.ppid}) called sys_clone")

def process_fopen_event(cpu, data, size):    
    event = bpf_proc["file_open_events"].event(data)
    print(f"File Name: {event.filename.decode()}, Process {event.comm.decode()} : (Timestamp: {event.timestamp}, PID: {event.pid}) called sys_openat")   


def main():
    bpf_proc["clone_events"].open_perf_buffer(process_clone_event)
    bpf_proc["file_open_events"].open_perf_buffer(process_fopen_event)
    print("Tracing for sys_clone()... Hit Ctrl-C to end.")
    while True:
        try:
            bpf_proc.perf_buffer_poll()
        except KeyboardInterrupt:
            break
main()
