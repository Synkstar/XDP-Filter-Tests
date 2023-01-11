CC = clang

BUILDDIR = build
SRCDIR = src

LIBBPFSRC = libbpf/src
LIBBPFOBJS = $(LIBBPFSRC)/staticobjs/bpf_prog_linfo.o $(LIBBPFSRC)/staticobjs/bpf.o $(LIBBPFSRC)/staticobjs/btf_dump.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/btf.o $(LIBBPFSRC)/staticobjs/hashmap.o $(LIBBPFSRC)/staticobjs/libbpf_errno.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/libbpf_probes.o $(LIBBPFSRC)/staticobjs/libbpf.o $(LIBBPFSRC)/staticobjs/netlink.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/nlattr.o $(LIBBPFSRC)/staticobjs/str_error.o

LOADERSRC = loader.c
LOADEROUT = xdpfilterstest
XDPPROGSRC = kern.c
XDPPROGBC = kern.bc
XDPPROGOBJ = kern.o

LDFLAGS += -lelf -lz -lconfig
INCS = -I $(LIBBPFSRC)

all: loader xdp

libbpf:
	$(MAKE) -C $(LIBBPFSRC)

loader: libbpf $(OBJS)
	mkdir -p $(BUILDDIR)/
	$(CC) $(LDFLAGS) $(INCS) -o $(BUILDDIR)/$(LOADEROUT) $(LIBBPFOBJS) $(SRCDIR)/$(LOADERSRC)

xdp:
	mkdir -p $(BUILDDIR)/
	$(CC) $(INCS) -D__BPF__ -O2 -D __BPF_TRACING__ -Wno-unused-value     -Wno-pointer-sign     -Wno-compare-distinct-pointer-types  -emit-llvm -c -g -o $(BUILDDIR)/$(XDPPROGBC) $(SRCDIR)/$(XDPPROGSRC)
	llc -march=bpf -filetype=obj -o $(BUILDDIR)/$(XDPPROGOBJ) $(BUILDDIR)/$(XDPPROGBC) 

clean:
	$(MAKE) -C $(LIBBPFSRC) clean
	rm -f $(BUILDDIR)/*.o $(BUILDDIR)/*.bc
	rm -f $(BUILDDIR)/$(LOADEROUT)

install:
	mkdir -p /etc/xdpfilterstest/
	cp $(BUILDDIR)/$(XDPPROGOBJ) /etc/xdpfilterstest/$(XDPPROGOBJ)
	cp $(BUILDDIR)/$(LOADEROUT) /usr/bin/$(LOADEROUT)
	cp data/xdpfilterstest.service /etc/systemd/system/

.PHONY: libbpf all
.DEFAULT: all