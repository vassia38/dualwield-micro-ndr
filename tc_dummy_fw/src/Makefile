# 1. Define a specific compiler for BPF. 
BPF_CC := clang

# 2. Define flags specifically for BPF.
# -target bpf: Generate BPF bytecode
# -O2: Required for BPF verifier optimization
# -g: Debug info
# -c: Compile only (don't link)
# -D__BPF_TRACING__: Often needed for headers
BPF_CFLAGS := -target bpf -O2 -g -c -D__BPF_TRACING__

# 3. The compilation rule
# We add $(CPPFLAGS) to pick up include paths (like libbpf) if OpenWrt sets them.
all: tc_dummy_fw.o
tc_dummy_fw.o: main.c
	$(BPF_CC) $(BPF_CFLAGS) $(CPPFLAGS) main.c -o tc_dummy_fw.o

# 4. Clean target
clean:
	rm -f *.o

