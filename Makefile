BPF_CLANG ?= clang
BPF_CFLAGS = -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 \
	-I/usr/include \
	-I/usr/include/x86_64-linux-gnu \
	-I/usr/src/linux-headers-$(shell uname -r)/include \
	-I/usr/src/linux-headers-$(shell uname -r)/arch/x86/include

LIBBPF_CFLAGS = $(shell pkg-config --cflags libbpf json-c)
LIBBPF_LDLIBS = $(shell pkg-config --libs libbpf json-c pthread)

all: daemon

# Compila o programa eBPF
syscall_monitor.bpf.o: syscall_monitor.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

# Gera esqueleto a partir do objeto BPF
syscall_monitor.skel.h: syscall_monitor.bpf.o
	/usr/lib/linux-tools-6.8.0-85/bpftool gen skeleton $< > $@

# Compila o daemon em C++ (pode trocar pra clang se preferir C)
daemon: daemon.cpp syscall_monitor.skel.h
	g++ -O2 -g -Wall -std=c++17 daemon.cpp -o $@ $(LIBBPF_CFLAGS) $(LIBBPF_LDLIBS) -ljson-c -lbpf -lelf -lz -pthread

clean:
	rm -f *.o *.skel.h daemon

