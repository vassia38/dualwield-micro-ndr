#include <stdint.h>

// 1. Exhaustive Kernel Type Definitions to bypass missing <asm/types.h>
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int8_t __s8;
typedef int16_t __s16;
typedef int32_t __s32;
typedef int64_t __s64;

// Kernel-specific networking types required by <linux/ip.h> and <linux/tcp.h>
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u16 __sum16;
typedef __u32 __wsum;

// 2. Safely include standard linux networking headers (No CO-RE)
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdbool.h>
/*
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif

#ifndef TC_ACT_UNSPEC
#define TC_ACT_UNSPEC -1
#endif
*/
// =================================
// Data Structures
// =================================

/*
struct bpf_map_def {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
  unsigned int map_flags;
};
*/

// define 5-tuple flow-key
struct flow_key {
  __u32 ip_a;
  __u32 ip_b;
  __u16 port_a;
  __u16 port_b;
  __u8 protocol;
};

// define flow statistics; vmlinux.h brings it over
struct flow_stats {
  __u64 pkts_a_to_b;
  __u64 bytes_a_to_b;
  __u64 pkts_b_to_a;
  __u64 bytes_b_to_a;
  __u64 start_time_ns;
  __u64 last_time_ns;
  __u8 tcp_flags; // cumuative bitwise OR of TCP flags
  __u8 initiator; // 0 for a, 1 for b
};

// =================================
// eBPF MAP DEFINITIONS (LEGACY SYNTAX)
// =================================
// we use SEC("maps") instead of SEC(".maps") to avoid the "failed to find
// valid kernel BTF" error on constrained OpenWRT builds

/*
// map to keep track of active flow
struct bpf_map_def SEC("maps") active_flows = {
    .type = BPF_MAP_TYPE_HASH,
    .max_entries = 4096, // reasonable for 128/256MB RAM
    .key_size = sizeof(struct flow_key),
    .value_size = sizeof(struct flow_stats),
};

// Perf Event Array to send data to userspace
struct bpf_map_def SEC("maps") flow_export_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 0, // dynamically sized by the loader per-CPU
};

// Define the dummy firewall map
// Key: IPv4 address (32-bit integer)
// Value: A dummy flag/counter (32-bit integer)
struct bpf_map_def SEC("maps") drop_ips_map = {
    .type = BPF_MAP_TYPE_HASH,
    .max_entries = 1024,
    .key_size = sizeof(struct flow_key),
    .value_size = sizeof(struct flow_stats),
};
*/

// map to keep track of active flow
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096); // reasonable for 128/256MB RAM
  __type(key, struct flow_key);
  __type(value, struct flow_stats);
} active_flows SEC(".maps");

// Perf Event Array to send data to userspace
/*
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} flow_export_events SEC(".maps");
*/

// Define the dummy firewall map
// Key: IPv4 address (32-bit integer)
// Value: A dummy flag/counter (32-bit integer)
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct flow_key);
  __type(value, __u32);
} drop_flows_map SEC(".maps");

// =================================
// PACKET PROCCESSING LOGIC
// =================================

SEC("tc")
int dualwield_enforcer(struct __sk_buff *skb) {
  // skb->data and skb->data_end are pointers to the raw packet data
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  // --- Parse Ethernet ---

  struct ethhdr *eth = data;

  // Bounds checking is strictly required by the eBPF verifier
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_OK;
  // Allow non-IPv4 traffic to pass through
  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return TC_ACT_OK;

  // --- Parse IPv4 ---

  struct iphdr *ip = (void *)(eth + 1);
  // Bounds checking for the IP header
  if ((void *)(ip + 1) > data_end)
    return TC_ACT_OK;

  __u32 src_ip = ip->saddr;
  __u32 dst_ip = ip->daddr;

  // --- Flow tracking ---
  //
  // Calculate the actual length of the IPv4 header
  // the 'ihl' field stores the length in 32-bit words; multiply by 4 to get
  // bytes...
  __u8 ip_hdr_len = ip->ihl * 4;

  // sanity check - An IP header must be at least 20bytes
  if (ip_hdr_len < sizeof(struct iphdr))
    return TC_ACT_OK;

  __u16 src_port = 0;
  __u16 dst_port = 0;
  __u8 flags = 0;

  // parse TCP ports
  if (ip->protocol == IPPROTO_TCP) {
    struct tcphdr *tcp = (void *)((__u8 *)ip + ip_hdr_len);
    // strictly check the TCP header is within packet bounds
    if ((void *)(tcp + 1) <= data_end) {
      src_port = tcp->source;
      dst_port = tcp->dest;
      flags = ((__u8 *)tcp)[13];
    }
  }
  // parse UDP ports
  else if (ip->protocol == IPPROTO_UDP) {
    struct udphdr *udp = (void *)((__u8 *)ip + ip_hdr_len);
    // strictly check bounds for udphdr
    if ((void *)(udp + 1) <= data_end) {
      src_port = udp->source;
      dst_port = udp->dest;
    }
  }

  struct flow_key fkey = {};
  fkey.protocol = ip->protocol;

  bool is_a_to_b =
      (src_ip < dst_ip) || (src_ip == dst_ip && src_port < dst_port);
  if (is_a_to_b) {
    fkey.ip_a = src_ip;
    fkey.ip_b = dst_ip;
    fkey.port_a = src_port;
    fkey.port_b = dst_port;
  } else {
    fkey.ip_a = dst_ip;
    fkey.ip_b = src_ip;
    fkey.port_a = dst_port;
    fkey.port_b = src_port;
  }

  // --- Quarantine check ---

  __u32 *is_blocked = bpf_map_lookup_elem(&drop_flows_map, &fkey);
  if (is_blocked)
    return TC_ACT_SHOT;

  // Update the flow statistics
  __u64 now = bpf_ktime_get_ns();
  struct flow_stats *stats = bpf_map_lookup_elem(&active_flows, &fkey);
  if (stats) {
    // Flow exists: atomically increment counters

    if (is_a_to_b) {
      __sync_fetch_and_add(&stats->pkts_a_to_b, 1);
      __sync_fetch_and_add(&stats->bytes_a_to_b, skb->len);
    } else {
      __sync_fetch_and_add(&stats->pkts_b_to_a, 1);
      __sync_fetch_and_add(&stats->bytes_b_to_a, skb->len);
    }

    // packets should almost always be steered to the same CPU core but even in
    // the case of a race condition, chances are same flag will be caught on the
    // very next packet so we are okay with the next line:
    stats->tcp_flags |= flags;
    stats->last_time_ns = now;
  } else {
    // New flow: init and insert
    struct flow_stats new_stats = {};
    if (is_a_to_b) {
      new_stats.pkts_a_to_b = 1;
      new_stats.bytes_a_to_b = skb->len;
      new_stats.initiator = 0;
    } else {
      new_stats.pkts_b_to_a = 1;
      new_stats.bytes_b_to_a = skb->len;
      new_stats.initiator = 1;
    }
    new_stats.start_time_ns = now;
    new_stats.last_time_ns = now;
    new_stats.tcp_flags = flags;

    bpf_map_update_elem(&active_flows, &fkey, &new_stats, BPF_ANY);
    // Optionally, notify userspace of a new connection via the Perf Buffer
    // bpf_perf_event_output(skb, &flow_export_events, BPF_F_CURRENT_CPU, &fkey,
    // sizeof(fkey));
  }

  // Pass the packet to the regular network stack
  return TC_ACT_OK;
}

// The kernel requires a GPL-compatible license to use certain BPF helpers
char __license[] SEC("license") = "GPL";
