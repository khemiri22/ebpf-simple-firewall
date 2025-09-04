// simple_firewall.c

/*
    * Simple Firewall eBPF Program
    * Drops packets from blocked IP addresses and logs the event.
    * 
    * This program uses a BPF hash map to store blocked IP addresses.
    * When a packet is received, it checks if the source IP is in the blocked list.
    * If it is, the packet is dropped and a debug event is logged.
    * Otherwise, the packet is allowed to pass.
    *
    * Compile with:
    * clang -O2 -target bpf -g -c simple_firewall.c -o simple_firewall.o
    * Note: -g is for debug info, uncomment SEC("license") and SEC("xdp") lines before compiling with clang.
    *
    * Load and attach with a Python script using BCC.
    *
*/

// Include necessary headers
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <linux/in.h>
#include <bcc/helpers.h>

// Define BPF maps
BPF_HASH(blocked_ips_map, __be32, __u8); // Key: blocked IP, Value: dummy
BPF_PERF_OUTPUT(debug_events); // For logging blocked events

// XDP program to drop packets from blocked IPs
// SEC("xdp")
int drop_bloced_ips_packets(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end; // End of packet data
    void *data = (void *)(long)ctx->data; // Start of packet data

    struct ethhdr *eth = data; // Ethernet header

    // Ensure we don't read beyond packet data
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS; // Allow the packet

    // Check if the packet is IP
    if (eth->h_proto != bpf_htons(ETH_P_IP)) // bpf_htons converts to network byte order (big-endian)
        return XDP_PASS; // Allow the packet

    // Parse IP header
    struct iphdr *iph = (struct iphdr *)(data + ETH_HLEN);

    // Ensure we don't read beyond packet data
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS; // Allow the packet

    // Check if source IP is in blocked list
    __u8 *value = blocked_ips_map.lookup(&iph->saddr);

    // If found, log the event and drop the packet
    if (value) {
        __be32 saddr_copy = iph->saddr; // Copy source IP for logging
        debug_events.perf_submit(ctx, &saddr_copy, sizeof(saddr_copy)); // Log the blocked IP
        return XDP_DROP; // Drop the packet
    }

    return XDP_PASS; // Allow the packet
}

// char _license[] SEC("license") = "GPL";
