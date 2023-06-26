BASEDIR = $(abspath ./)
BTFFILE = /sys/kernel/btf/vmlinux
BPFTOOL = $(shell which bpftool)
ARCH := $(shell uname -m | sed 's/x86_64/amd64/g; s/aarch64/arm64/g')
CBPFFILENAME = main.bpf.o
VMLINUXH = ./vmlinux.h
LIBBPFPATH = $(BASEDIR)/libbpfso

one-make:
	make c2bpf
	make bpf2go

bpf2go:
	CC=clang \
		CGO_CFLAGS="-I$(LIBBPFPATH)/" \
		CGO_LDFLAGS="-lelf -lz $(LIBBPFPATH)/libbpf.a" \
		GOOS=linux GOARCH=$(ARCH) \
		go build \
		-tags netgo -ldflags '-w -extldflags "-static"' \
		-o rss_stat \
		./main.go

c2bpf:
	clang -g -O2 -c -target bpf -o $(CBPFFILENAME) main.bpf.c

con-vmlinux:
	@if [ ! -f $(BTFFILE) ]; then \
		echo "ERROR: kernel does not seem to support BTF"; \
		exit 1; \
    fi
	@if [ ! -f $(VMLINUXH) ]; then \
		if [ ! $(BPFTOOL) ]; then \
			echo "ERROR: could not find bpftool, but can be installed with: \n"; \
			     "	  sudo apt install linux-tools-generic"; \
			exit 1; \
		fi; \
		echo "INFO: generating $(VMLINUXH) from $(BTFFILE)"; \
		$(BPFTOOL) btf dump file $(BTFFILE) format c > $(VMLINUXH); \
	fi

build-bpf:
	CC="gcc" CFLAGS="-g -O2 -Wall -fpie" LD_FLAGS="" \
       /usr/bin/make -C ./libbpf/src \
    	BUILD_STATIC_ONLY=1 \
    	OBJDIR=$(LIBBPFPATH)/libbpf \
    	DESTDIR=$(LIBBPFPATH) \
    	INCLUDEDIR= LIBDIR= UAPIDIR= install