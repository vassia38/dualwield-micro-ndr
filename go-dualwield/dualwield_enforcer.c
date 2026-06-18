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

// =================================
// Data Structures
// =================================

// define 5-tuple flow-key
struct flow_key {
  __u32 ip_a;
  __u32 ip_b;
  __u16 port_a;
  __u16 port_b;
  __u8 protocol;
};

// flow statistics (defined manually here; no vmlinux.h / CO-RE)
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
// eBPF MAP DEFINITIONS
// =================================
// SEC(".maps") does NOT require kernel BTF at load time. Type information
// is embedded by clang in the ELF at compile time (ELF BTF), independently
// of /sys/kernel/btf/vmlinux. The "failed to find valid kernel BTF" error
// is caused by CO-RE relocations and vmlinux.h usage, not by map declarations.
// The typedefs above replace vmlinux.h, eliminating all CO-RE dependencies.

// map to keep track of active flow
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096); // reasonable for 128/256MB RAM
  __type(key, struct flow_key);
  __type(value, struct flow_stats);
} active_flows SEC(".maps");

// Define the dummy firewall map
// Key: IPv4 address (32-bit integer)
// Value: A dummy flag/counter (32-bit integer)
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct flow_key);
  __type(value, __u32);
} drop_flows_map SEC(".maps");

// LPM trie key for the IPv4 allowlist. addr holds the four address bytes in
// network order; on this little-endian target that is exactly the raw value
// read from ip->saddr/ip->daddr (same layout as the flow_key IPs). The kernel
// LPM trie matches the most-significant `prefixlen` bits of addr, so the first
// address octet must be the most significant byte, which it is on LE.
struct lpm_v4_key {
  __u32 prefixlen;
  __u32 addr;
};

// Allowlist of trusted addresses/CIDRs that must never be scored or blocked
// (router's own IPs, default gateway, DNS resolvers, loopback, plus any
// user-supplied entries). It is consulted FIRST in the datapath: a match returns
// TC_ACT_OK before any drop lookup or flow accounting, so trusted infrastructure
// can never be quarantined - even if a bad rule reaches the banlist - and
// management traffic never fills the 4096-entry flow table.
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 4096);
  __type(key, struct lpm_v4_key);
  __type(value, __u32);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} allowlist_v4 SEC(".maps");

// Known-bad addresses/CIDRs from threat-intelligence feeds (Spamhaus DROP,
// abuse.ch, Emerging Threats, FireHOL, CINS, ...). Checked AFTER the allowlist,
// so a trusted address always wins over a feed false-positive; a match drops the
// packet. This is the signature layer - reputation of known-bad IPs - that
// complements the behavioural ML: deterministic, low-FP blocking that does not
// depend on the drifting classifier. Sized larger than the allowlist because
// consolidated feeds run to tens of thousands of entries.
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, 65536);
  __type(key, struct lpm_v4_key);
  __type(value, __u32);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} blocklist_v4 SEC(".maps");

// Drop counters for observability: index 0 = reputation blocklist, 1 = ML/banlist
// quarantine. PERCPU so the increment is lock-free on the datapath; userspace sums
// across CPUs. Lets Chapter 6 quantify how much traffic each layer actually dropped.
#define DROP_STAT_REPUTATION 0
#define DROP_STAT_QUARANTINE 1
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 2);
  __type(key, __u32);
  __type(value, __u64);
} drop_stats SEC(".maps");

static __inline void count_drop(__u32 idx) {
  __u64 *c = bpf_map_lookup_elem(&drop_stats, &idx);
  if (c)
    (*c)++;
}

// Helper: create a canonical flow_key from two IPs and ports. This is the SINGLE
// source of the ordering rule; the packet path calls it instead of inlining its
// own copy, and the Go loader mirrors it in makeCanonicalKey. Comparison is on the
// raw network-order values (ports as read from the header / produced by htons).
// Returns true if (ip1,p1) became endpoint a, so the caller can tell direction.
static __inline bool make_canonical(__u32 ip1, __u32 ip2, __u16 p1, __u16 p2, __u8 proto, struct flow_key *out) {
  bool first_is_a = (ip1 < ip2) || (ip1 == ip2 && p1 <= p2);
  if (first_is_a) {
    out->ip_a = ip1;
    out->ip_b = ip2;
    out->port_a = p1;
    out->port_b = p2;
  } else {
    out->ip_a = ip2;
    out->ip_b = ip1;
    out->port_a = p2;
    out->port_b = p1;
  }
  out->protocol = proto;
  return first_is_a;
}

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

  __u16 h_proto = eth->h_proto;
  void *l3 = (void *)(eth + 1);

  // Unwrap a single 802.1Q / 802.1ad VLAN tag if present, so tagged IPv4 traffic
  // is still inspected and enforceable rather than passing through unseen.
  // (QinQ double-tagging is rare and left unhandled.)
  if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
    struct vlan_hdr {
      __be16 h_vlan_TCI;
      __be16 h_vlan_encapsulated_proto;
    };
    struct vlan_hdr *vhdr = l3;
    if ((void *)(vhdr + 1) > data_end)
      return TC_ACT_OK;
    h_proto = vhdr->h_vlan_encapsulated_proto;
    l3 = (void *)(vhdr + 1);
  }

  // Allow non-IPv4 traffic to pass through. IPv6 is intentionally out of scope:
  // it is passed unfiltered (a documented limitation - the flow model, maps and
  // ML features are all IPv4). On a dual-stack link this is a blind spot.
  if (h_proto != bpf_htons(ETH_P_IP))
    return TC_ACT_OK;

  // --- Parse IPv4 ---

  struct iphdr *ip = l3;
  // Bounds checking for the IP header
  if ((void *)(ip + 1) > data_end)
    return TC_ACT_OK;

  __u32 src_ip = ip->saddr;
  __u32 dst_ip = ip->daddr;

  // NetFlow IN_BYTES/OUT_BYTES count L3 bytes (IP header + payload) - the same
  // semantics nProbe used when building NF-UQ-NIDS-v2. skb->len includes the
  // 14-byte Ethernet header, which systematically inflated every byte feature
  // (worst on small packets: ~25% on a 60-byte frame). ip->tot_len is the
  // on-wire IP datagram length and matches the training feature exactly.
  // Caveat: assumes flow offloading is disabled (as in the Chapter 6 testbed);
  // GRO could coalesce segments so a single skb reports one tot_len.
  __u32 l3_len = bpf_ntohs(ip->tot_len);

  // --- Allowlist short-circuit ---
  // If either endpoint is trusted, pass immediately: no block, no accounting.
  // This runs before the quarantine lookups so the allowlist always overrides a
  // ban, protecting the gateway/router from a misclassified self-block.
  struct lpm_v4_key akey = {};
  akey.prefixlen = 32;
  akey.addr = src_ip;
  if (bpf_map_lookup_elem(&allowlist_v4, &akey))
    return TC_ACT_OK;
  akey.addr = dst_ip;
  if (bpf_map_lookup_elem(&allowlist_v4, &akey))
    return TC_ACT_OK;

  // --- Threat-intel blocklist ---
  // Known-bad source or destination: drop. The allowlist above already had
  // priority, so a trusted address is never dropped here. Reuses akey (prefixlen
  // is still 32 from the allowlist lookups).
  akey.addr = src_ip;
  if (bpf_map_lookup_elem(&blocklist_v4, &akey)) {
    count_drop(DROP_STAT_REPUTATION);
    return TC_ACT_SHOT;
  }
  akey.addr = dst_ip;
  if (bpf_map_lookup_elem(&blocklist_v4, &akey)) {
    count_drop(DROP_STAT_REPUTATION);
    return TC_ACT_SHOT;
  }

  // --- Flow tracking ---
  //
  // Calculate the actual length of the IPv4 header
  // the 'ihl' field stores the length in 32-bit words; multiply by 4 to get
  // bytes...
  __u8 ip_hdr_len = ip->ihl * 4;

  // sanity check - An IP header must be at least 20bytes
  if (ip_hdr_len < sizeof(struct iphdr))
    return TC_ACT_OK;

  // Non-initial IP fragments carry no L4 header: reading the L4 offset would
  // interpret payload bytes as ports. Only the first fragment (offset 0) has the
  // ports; later fragments are tracked by IP+protocol with ports left at 0.
  bool has_l4 = (bpf_ntohs(ip->frag_off) & 0x1FFF) == 0;

  __u16 src_port = 0;
  __u16 dst_port = 0;
  __u8 flags = 0;

  // parse TCP ports
  if (has_l4 && ip->protocol == IPPROTO_TCP) {
    struct tcphdr *tcp = (void *)((__u8 *)ip + ip_hdr_len);
    // strictly check the TCP header is within packet bounds
    if ((void *)(tcp + 1) <= data_end) {
      src_port = tcp->source;
      dst_port = tcp->dest;
      flags = ((__u8 *)tcp)[13];
    }
  }
  // parse UDP ports
  else if (has_l4 && ip->protocol == IPPROTO_UDP) {
    struct udphdr *udp = (void *)((__u8 *)ip + ip_hdr_len);
    // strictly check bounds for udphdr
    if ((void *)(udp + 1) <= data_end) {
      src_port = udp->source;
      dst_port = udp->dest;
    }
  }

  // Build the canonical key via the shared helper (the Go loader mirrors the same
  // ordering), and learn the direction for the per-direction counters below.
  struct flow_key fkey = {};
  bool is_a_to_b = make_canonical(src_ip, dst_ip, src_port, dst_port, ip->protocol, &fkey);

  // --- Quarantine check ---

  // The drop map supports three ban granularities, each a key built with the same
  // canonicalization as on insert. None of these are dead: patterns (1)/(2) are
  // produced by the ML quarantine path (exact 5-tuple, and port-wildcard IP-pair
  // for DDoS), and pattern (3) is produced by IP-wildcard banlist entries such as
  // "6,1.2.3.4,*,0.0.0.0,*" and by the (planned) role-aware quarantine of a
  // compromised host. Cost note for Chapter 6.4: this is up to four drop-map
  // lookups per packet on top of the two allowlist and two blocklist lookups.
  struct flow_key try = {};
  __u32 *is_blocked = NULL;

  // 1) exact 5-tuple match
  is_blocked = bpf_map_lookup_elem(&drop_flows_map, &fkey);
  if (is_blocked) {
    count_drop(DROP_STAT_QUARANTINE);
    return TC_ACT_SHOT;
  }

  // 2) wildcard ports between the same IP pair (port_a=0, port_b=0)
  make_canonical(fkey.ip_a, fkey.ip_b, 0, 0, fkey.protocol, &try);
  is_blocked = bpf_map_lookup_elem(&drop_flows_map, &try);
  if (is_blocked) {
    count_drop(DROP_STAT_QUARANTINE);
    return TC_ACT_SHOT;
  }

  // 3) IP wildcard: one address to/from anywhere (the other ip and both ports 0).
  // Try both src and dst as the banned address.
  make_canonical(src_ip, 0, 0, 0, fkey.protocol, &try);
  is_blocked = bpf_map_lookup_elem(&drop_flows_map, &try);
  if (is_blocked) {
    count_drop(DROP_STAT_QUARANTINE);
    return TC_ACT_SHOT;
  }

  make_canonical(dst_ip, 0, 0, 0, fkey.protocol, &try);
  is_blocked = bpf_map_lookup_elem(&drop_flows_map, &try);
  if (is_blocked) {
    count_drop(DROP_STAT_QUARANTINE);
    return TC_ACT_SHOT;
  }

  // Update the flow statistics
  __u64 now = bpf_ktime_get_ns();
  struct flow_stats *stats = bpf_map_lookup_elem(&active_flows, &fkey);
  if (stats) {
    // Flow exists: atomically increment counters

    if (is_a_to_b) {
      __sync_fetch_and_add(&stats->pkts_a_to_b, 1);
      __sync_fetch_and_add(&stats->bytes_a_to_b, l3_len);
    } else {
      __sync_fetch_and_add(&stats->pkts_b_to_a, 1);
      __sync_fetch_and_add(&stats->bytes_b_to_a, l3_len);
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
      new_stats.bytes_a_to_b = l3_len;
      new_stats.initiator = 0;
    } else {
      new_stats.pkts_b_to_a = 1;
      new_stats.bytes_b_to_a = l3_len;
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
