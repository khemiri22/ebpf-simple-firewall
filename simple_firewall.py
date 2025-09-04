#!/usr/bin/env python3

# Import necessary libraries
from bcc import BPF
from pathlib import Path
import ctypes
import socket
import struct

# Load and compile the eBPF program
def load_bpf_program():
    bpf_source = Path('./simple_firewall.c').read_text()
    bpf = BPF(text=bpf_source, cflags=["-w"]) # -w to suppress warnings
    return bpf

# Attach the eBPF program to the specified network interface
def attach_xdp_program(bpf, interface, ebpf_prog_fn_name):
    xdp_fn = bpf.load_func(ebpf_prog_fn_name, BPF.XDP)
    bpf.attach_xdp(interface, xdp_fn, 0)
    return bpf

# Detach the eBPF program from the specified network interface
def detach_xdp_program(bpf, interface):
    bpf.remove_xdp(interface, 0)

# Callback function to print debug events
def print_debug_event(cpu, data, size):
    src_ip = ctypes.cast(data, ctypes.POINTER(ctypes.c_uint32)).contents.value
    print(f"Packet from {socket.inet_ntoa(struct.pack('I', src_ip))} dropped")

# Function to add an IP address to the block list
def block_ip(bpf, ip_addr_str):
    ip_addr = struct.unpack("I", socket.inet_aton(ip_addr_str))[0] 
    bpf["blocked_ips_map"][ctypes.c_uint32(ip_addr)] = ctypes.c_uint8(1)
    print(f"Blocked IP added: {ip_addr_str}")

def main():
    INTERFACE = "enp0s3"
    # IPs block list - add IPs you want to block here (example : ["192.168.59.192","192.168.59.180"] )
    block_list = ["8.8.8.8", "1.1.1.1"] # Example IPs to block (google DNS and Cloudflare DNS)

    # Load and attach eBPF program
    bpf = load_bpf_program()
    for ip in block_list:
        block_ip(bpf, ip)
    attach_xdp_program(bpf, INTERFACE, "drop_bloced_ips_packets")

    # Set up perf buffer for debug events
    bpf["debug_events"].open_perf_buffer(print_debug_event)

    try:
        print("press Ctrl+C to stop...")
        while True:
            bpf.perf_buffer_poll(1) # Poll for events
    except (KeyboardInterrupt) as e:
        print("Detaching eBPF program and exiting.")
        detach_xdp_program(bpf, INTERFACE) # Detach the program

if __name__ == "__main__":
    main()
