#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_UNSPEC -1
#define ETH_P_IP 0x0800
// define 5-tuple flow-key
struct flow_key {
  __u32 src_ip;
  __u32 dest_ip;
  __u16 src_port;
  __u16 dest_port;
  __u8 protocol;
};

// define flow statistics; vmlinux.h brings it over
// struct flow_stats {
//  __u64 packets;
//  __u64 bytes;
//};

// map to keep track of active flow
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096); // reasonable for 128/256MB RAM
  __type(key, struct flow_key);
  __type(value, struct flow_stats);
} active_flows SEC(".maps");

// Perf Event Array to send data to userspace
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} flow_export_events SEC(".maps");

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

  // 4. If the packet was not blocked, we track it

  struct flow_key fkey = {};
  fkey.src_ip = ip->saddr;
  fkey.dest_ip = ip->daddr;
  fkey.protocol = ip->protocol;
  fkey.src_port = 0;
  fkey.dest_port = 0;

  // Calculate the actual length of the IPv4 header
  // the 'ihl' field stores the length in 32-bit words; multiply by 4 to get
  // bytes...
  __u8 ip_hdr_len = ip->ihl * 4;

  // sanity check - An IP header must be at least 20bytes
  if (ip_hdr_len < sizeof(struct iphdr)) {
    return TC_ACT_OK;
  }

  // parse TCP ports
  if (ip->protocol == IPPROTO_TCP) {
    struct tcphdr *tcp = (void *)((__u8 *)ip + ip_hdr_len);

    // strictly check the TCP header is within pacxket Bounds
    if ((void *)(tcp + 1) > data_end) {
      return TC_ACT_OK;
    }

    // ports in network byte order
    fkey.src_port = tcp->source;
    fkey.dest_port = tcp->dest;
  } else if (ip->protocol == IPPROTO_UDP) {
    struct udphdr *udp = (void *)((__u8 *)ip + ip_hdr_len);

    // strictly check bounds for udphdr
    if ((void *)(udp + 1) > data_end) {
      return TC_ACT_OK;
    }

    fkey.src_port = udp->source;
    fkey.dest_port = udp->dest;
  }

  // Lookup existing flow
  struct flow_stats *stats = bpf_map_lookup_elem(&active_flows, &fkey);
  if (stats) {
    __sync_fetch_and_add(&stats->pkts, 1);
    __sync_fetch_and_add(&stats->bytes, skb->len);
  } else {
    struct flow_stats new_stats = {1, skb->len};
    bpf_map_update_elem(&active_flows, &fkey, &new_stats, BPF_ANY);
    // Optionally, notify userspace of a new connection via the Perf Buffer
    bpf_perf_event_output(skb, &flow_export_events, BPF_F_CURRENT_CPU, &fkey,
                          sizeof(fkey));
  }

  // Pass the packet to the regular network stack
  return TC_ACT_OK;
}

// The kernel requires a GPL-compatible license to use certain BPF helpers
char __license[] SEC("license") = "GPL";
