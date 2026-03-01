# eBPF TC dummy fw
## 1. Prerequisites
### on the openwrt  machine
bpftool, kmod-sched-bpf, kmod-sched-core, tc-bpf

## 2. Loading and attaching via TC:
```sh
tc qdisc add dev <interface> clsact`
tc filter add dev <interface> ingress bpf da obj tc_dummy_fw.o sec tc
```
## 3. Interacting with maps
```sh
bpftool map show
bpftool map dump id <MAP_ID>
# keep network bytes order (192.168.1.1 = c0 a8 01 01)
bpftool map update id <MAP_ID> key hex 00 00 00 00 value hex 01 00 00 00
bpftool map delete id <MAP_ID> key hex 00 00 00 00
```
## 4. Unloading
```sh
tc qdisc del dev <interface> clsact
```

find output object in <br/>
```sh
build_dir/target-mipsel_24kc_musl/tc_dummy_fw/.pkgdir/tc_dummy_fw/bin/tc_dummy_fw.o
```

## info
`__sync_fetch_and_add` is actually a compiler built-in (an intrinsic function) provided directly by Clang and GCC. When you use this function, Clang doesn't look for it in an external library. Instead, it translates it directly into a specific hardware instruction. For eBPF, it translates into the eBPF atomic add instruction (`BPF_XADD`). </br>
We need it for concurrency - MT7621 hass a multi-core

