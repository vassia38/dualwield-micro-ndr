#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Define the dummy firewall map
// Key: IPv4 address (32-bit integer)
// Value: A dummy flag/counter (32-bit integer)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} drop_ips_map SEC(".maps");

SEC("tc")
int dummy_firewall(struct __sk_buff *skb) {
    // skb->data and skb->data_end are pointers to the raw packet data
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // 1. Parse Ethernet Header
    struct ethhdr *eth = data;
    
    // Bounds checking is strictly required by the eBPF verifier
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // Allow non-IPv4 traffic to pass through
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    // 2. Parse IPv4 Header
    struct iphdr *ip = (void *)(eth + 1);
    
    // Bounds checking for the IP header
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    __u32 src_ip = ip->saddr;

    // 3. Map Lookup
    __u32 *value = bpf_map_lookup_elem(&drop_ips_map, &src_ip);
    if (value) {
        // Source IP is in our dummy map! Drop the packet.
        // *value could be incremented here to track drop counts if desired.
        return TC_ACT_SHOT;
    }

    // Pass the packet to the regular network stack
    return TC_ACT_OK;
}

// The kernel requires a GPL-compatible license to use certain BPF helpers
char __license[] SEC("license") = "GPL";
