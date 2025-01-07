from bcc import BPF
from pathlib import Path
import socket
from struct import unpack
import pyroute2
import os
import threading
import copy
import ctypes
import signal
class ProcessInfo:
    def __init__(self, ppid, pid, process_name):
        self.ppid = ppid
        self.pid = pid
        self.process_name = process_name
        self.open_filename_list = []
        self.read_filename_list = []
        self.write_filename_list = []
        self.dest_ip_list = []
        self.dest_port_list = []
        self.total_packet_size_sent = 0
        self.lock = threading.Lock()
        
    def update_open_filename_list(self, filename):
        with self.lock:
            if(filename not in self.open_filename_list):
                self.open_filename_list.append(filename)
    def update_read_filename_list(self, filename):
        with self.lock:
            if(filename not in self.read_filename_list):
                self.read_filename_list.append(filename)
    def update_write_filename_list(self, filename):
        with self.lock:
            if(filename not in self.write_filename_list):
                self.write_filename_list.append(filename)
    def update_socket_info(self, dst_ip, dst_port, packet_size):
        with self.lock:
            if(dst_ip not in self.dest_ip_list and dst_ip != '127.0.0.1' and dst_ip != '0.0.0.0'):
                self.dest_ip_list.append(dst_ip)
                self.dest_port_list.append(dst_port)
            if(dst_ip != '127.0.0.1' or dst_ip != '0.0.0.0'):
                self.total_packet_size_sent += packet_size
        


# global dictionary to map pid to ProcessInfo
processInfoMap = {}

list_lock = threading.Lock()
# global list of blocked ip's
blocked_ip_list = []
def update_blocked_ip_list(ip_list):
    global blocked_ip_list
    with list_lock:
        blocked_ip_list = copy.deepcopy(ip_list)
    
# process monitor (monitorig process through syscalls clone, open, read and write)
class ProcessMonitor:
    def __init__(self,path):
        self.src = Path(path).read_text()
        self.bpf_proc = BPF(text=self.src)
        self.lock = threading.Lock()

    def process_clone_event(self,cpu, data, size):
        event = self.bpf_proc["clone_events"].event(data)
        with self.lock:
            if(processInfoMap.get(event.pid) == None):
                pInfo = ProcessInfo(event.ppid, event.pid, event.comm.decode())
                processInfoMap[event.pid] = pInfo
        if(event.comm.decode() == "ransomware"):
            print(f"Process {event.comm.decode()} (PID: {event.pid}, PPID: {event.ppid}) called sys_clone")

    def process_fopen_event(self,cpu, data, size):  
        event = self.bpf_proc["file_open_events"].event(data)
        with self.lock:
            if(processInfoMap.get(event.pid) == None):
                pInfo = ProcessInfo(event.ppid, event.pid, event.comm.decode())
                processInfoMap[event.pid] = pInfo
                pInfo.update_open_filename_list(event.filename.decode())
            else:
                pInfo = processInfoMap.get(event.pid)
                pInfo.update_open_filename_list(event.filename.decode())
                #print(pInfo)
        if(event.comm.decode() == "ransomware"):
            pass
            #print(f"SYS_OPENAT ::: Timestamp: {event.timestamp}, PID: {event.pid}, File Name: {event.filename.decode()}, Process: {event.comm.decode()}, FD: {event.fd}")
    
    def process_fread_event(self,cpu, data, size):
        event = self.bpf_proc["file_read_events"].event(data)
        with self.lock:
            if(processInfoMap.get(event.pid) == None):
                pInfo = ProcessInfo(event.ppid, event.pid, event.comm.decode())
                processInfoMap[event.pid] = pInfo
                pInfo.update_read_filename_list(event.filename.decode())
            else:
                pInfo = processInfoMap.get(event.pid)
                pInfo.update_read_filename_list(event.filename.decode())
        if(event.comm.decode() == "ransomware"):
            pass
            #print(f"SYS_READ ::: Timestamp: {event.timestamp}, PID: {event.pid}, File Name: {event.filename.decode()}, Process: {event.comm.decode()}, PID_FD: {event.fd}")

    def process_fwrite_event(self,cpu, data, size):
        event = self.bpf_proc["file_write_events"].event(data)
        with self.lock:
            if(processInfoMap.get(event.pid) == None):
                pInfo = ProcessInfo(event.ppid, event.pid, event.comm.decode())
                processInfoMap[event.pid] = pInfo
                pInfo.update_write_filename_list(event.filename.decode())
            else:
                pInfo = processInfoMap.get(event.pid)
                pInfo.update_write_filename_list(event.filename.decode())
        if(len(pInfo.write_filename_list) > 5 and event.comm.decode() == "ransomware"):
            try:
                os.kill(event.pid, signal.SIGKILL)
                print(f"Killed a probable ransomware process with pid {event.pid} and process name {event.comm.decode()}")
            except Exception as e:
                print("Killing process failed:: ",e)

        if(event.comm.decode() == "ransomware"):
            pass
           #print(f"SYS_WRITE ::: Timestamp: {event.timestamp}, PID: {event.pid}, File Name: {event.filename.decode()}, Process: {event.comm.decode()}, PID_FD: {event.fd}")

    def start(self):
        self.bpf_proc["clone_events"].open_perf_buffer(self.process_clone_event, page_cnt=1024)
        self.bpf_proc["file_open_events"].open_perf_buffer(self.process_fopen_event, page_cnt=1024)
        self.bpf_proc["file_read_events"].open_perf_buffer(self.process_fread_event, page_cnt=1024)
        self.bpf_proc["file_write_events"].open_perf_buffer(self.process_fwrite_event, page_cnt=1024)

        return self.bpf_proc
    def stop(self):
        # Close the perf buffers and reset
        self.bpf_proc["clone_events"].close_perf_buffer()
        self.bpf_proc["file_open_events"].close_perf_buffer()
        self.bpf_proc["file_read_events"].close_perf_buffer()
        self.bpf_proc["file_write_events"].close_perf_buffer()

class SocketMonitor:
    def __init__(self,path_tcp,path_udp):
        self.src_tcp = Path(path_tcp).read_text()
        self.src_udp = Path(path_udp).read_text()
        self.bpf_tcp = BPF(text=self.src_tcp)
        self.bpf_udp = BPF(text=self.src_udp)
        self.lock = threading.Lock()
    # Attach kprobe to udp_sendmsg and udp_recvmsg
    def attach_kprobe(self):
        self.bpf_tcp.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")
        self.bpf_udp.attach_kprobe(event="udp_sendmsg", fn_name="trace_tcp_sendmsg")
    def int_to_ip(self,int_ip):
        return socket.inet_ntop(socket.AF_INET, int_ip.to_bytes(4, 'big'))
    def socket_event_tcp(self,cpu, data, size):
        event = self.bpf_tcp["packet_info"].event(data)
        with self.lock:
            if(processInfoMap.get(event.pid) == None):
                pInfo = ProcessInfo(event.ppid, event.pid, event.comm.decode())
                pInfo.update_socket_info(self.int_to_ip(event.dst_ip), event.dst_port, event.pkt_len)
                processInfoMap[event.pid] = pInfo
            else:
                pInfo = processInfoMap.get(event.pid)
                pInfo.update_socket_info(self.int_to_ip(event.dst_ip), event.dst_port, event.pkt_len)
            if(pInfo.total_packet_size_sent >= 256 and self.int_to_ip(event.dst_ip) == '92.108.232.172'):
                update_blocked_ip_list(pInfo.dest_ip_list)
        if(event.comm.decode() == "ransomware"):
            print(f"TCP ::: Timestamp: {event.timestamp}, PID: {event.pid}, Source IP: {self.int_to_ip(event.src_ip)}, Dest IP: {self.int_to_ip(event.dst_ip)}, Src Port: {event.src_port}, Dst Port: {event.dst_port}, PacketLength: {event.pkt_len}")

    def socket_event_udp(self,cpu, data, size):
        event = self.bpf_udp["packet_info"].event(data)
        with self.lock:
            if(processInfoMap.get(event.pid) == None):
                pInfo = ProcessInfo(event.ppid, event.pid, event.comm.decode())
                pInfo.update_socket_info(self.int_to_ip(event.dst_ip), event.dst_port, event.pkt_len)
                processInfoMap[event.pid] = pInfo
            else:
                pInfo = processInfoMap.get(event.pid)
                pInfo.update_socket_info(self.int_to_ip(event.dst_ip), event.dst_port, event.pkt_len)
            if(pInfo.total_packet_size_sent >= 1024 and self.int_to_ip(event.dst_ip) == '92.108.232.172'):
                update_blocked_ip_list(pInfo.dest_ip_list)
        if(event.comm.decode() == "ransomware"):
            print(f"UDP ::: Timestamp: {event.timestamp}, PID: {event.pid}, Source IP: {self.int_to_ip(event.src_ip)}, Dest IP: {self.int_to_ip(event.dst_ip)}, Src Port: {event.src_port}, Dst Port: {event.dst_port}")

    def start(self):
        self.attach_kprobe()
        self.bpf_tcp["packet_info"].open_perf_buffer(self.socket_event_tcp, page_cnt=1024)
        self.bpf_udp["packet_info"].open_perf_buffer(self.socket_event_udp, page_cnt=1024)
        return (self.bpf_tcp, self.bpf_udp)
    def stop(self):
        # Close the perf buffers and reset
        self.bpf_proc["packet_info"].close_perf_buffer()

class TransmissionControlMonitor:
    def __init__(self, tcegress_path, interface):
        self.src_tc = Path(tcegress_path).read_text()
        self.bpf = BPF(text=self.src_tc)
        self.interface = interface
        self.ip = None
        self.ipdb = None
        self.idx = None
    def ip_to_int(self, ip_str):
        packed_ip = socket.inet_pton(socket.AF_INET, ip_str)
        return int.from_bytes(packed_ip, 'big')
    def int_to_ip(self, int_ip):
        return socket.inet_ntop(socket.AF_INET, int_ip.to_bytes(4, 'big'))
    def tc_event(self,cpu, data, size):
        event = self.bpf["packet_info"].event(data)
        if(self.int_to_ip(event.dst_ip) == '92.108.232.172'):
            print(f"Protocol: {event.protocol} ::: Source IP: {self.int_to_ip(event.src_ip)}, Dest IP: {self.int_to_ip(event.dst_ip)}, Src Port: {event.src_port}, Dst Port: {event.dst_port}, Packet_Killed: {event.packet_killed}")
        with list_lock:
            blocked_map = self.bpf["blocked_ip_map"]
            for i,val in enumerate(blocked_ip_list):
                key = ctypes.c_uint32(self.ip_to_int(val))
                value = ctypes.c_uint32(1)
                blocked_map[key] = value
    def create_tc(self,interface):
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
    
    def start(self):
        self.ip, self.ipdb, self.idx = self.create_tc(self.interface)
        # loading TC
        fn = self.bpf.load_func("handle_egress", BPF.SCHED_CLS)
        self.ip.tc("add-filter", "bpf", self.idx, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff3", classid=1, direct_action=True)

        self.bpf["packet_info"].open_perf_buffer(self.tc_event, page_cnt=1024)
        return self.bpf
    
    def cleanup(self):
        ip_l = self.ip
        idx_l = self.idx
        ipdb_l = self.ipdb
        ip_l.tc("del", "clsact", idx_l)
        ipdb_l.release()

def printEntireProcessDictionary():
    for key, value in processInfoMap.items():
        if(value.process_name == "ransomware"):
            print(f"PID:{value.pid} Process Name: {value.process_name}")
            print("-----------------------------------------------------")
            print(f"        PPID List: {value.ppid}")
            print(f"        Open File List: {len(value.open_filename_list)}")
            print(f"        Read File List: {len(value.read_filename_list)}")
            print(f"        Write File List: {value.write_filename_list } : {len(value.write_filename_list)}")
            print(f"        Dst IP List: {value.dest_ip_list}")
            print(f"        Total Packets Sent: {value.total_packet_size_sent}")
            print("-----------------------------------------------------")
def main():
    process_monitor = ProcessMonitor("./ProcessFilter/prochook.c")
    bpf_proc = process_monitor.start()
    
    socket_monitor = SocketMonitor("./NetworkFilter/sock.c","./NetworkFilter/sock.c")
    bpf_tcp_socket, bpf_udp_socket = socket_monitor.start()

    tc_monitor = TransmissionControlMonitor("./NetworkFilter/tc_egress.c","wlp114s0")
    bpf_tc = tc_monitor.start()

    print("[+] Monitoring started\n")
    while True:
        try:
            bpf_proc.perf_buffer_poll()
            bpf_tcp_socket.perf_buffer_poll()
            bpf_udp_socket.perf_buffer_poll()
            bpf_tc.perf_buffer_poll()
        except KeyboardInterrupt:
            print("[+] Stopping...")
            break
        except Exception as e:
            print(e)
            break

    #process_monitor.stop()
    #socket_monitor.stop()    
    tc_monitor.cleanup()
    printEntireProcessDictionary()
        

if __name__ == "__main__":
    main()



    