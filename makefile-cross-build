.PHONY: all toolchain libpcap setup-env zzz clean

ifndef ARCH
$(error ARCH is not set. Usage: make ARCH=<arch> [all])
endif

ifeq ($(ARCH),armv7)
TOOLCHAIN_NAME := arm-linux-musleabihf-cross
else ifeq ($(ARCH),aarch64)
TOOLCHAIN_NAME := aarch64-linux-musl-cross
else ifeq ($(ARCH),x86_64)
TOOLCHAIN_NAME := x86_64-linux-musl-cross
else ifeq ($(ARCH),i686)
TOOLCHAIN_NAME := i686-linux-musl-cross
else ifeq ($(ARCH),mipsel)
TOOLCHAIN_NAME := mipsel-linux-muslsf-cross
else ifeq ($(ARCH),mips64)
TOOLCHAIN_NAME := mips64-linux-musl-cross
else ifeq ($(ARCH),riscv64)
TOOLCHAIN_NAME := riscv64-linux-musl-cross
else
$(error Unsupported ARCH '$(ARCH)'. Supported: armv7 aarch64 x86_64 i686 mips64 mispel riscv64)
endif

TRIPLET       := $(patsubst %-cross,%,$(TOOLCHAIN_NAME))
CROSS_URL     := https://musl.cc/$(TOOLCHAIN_NAME).tgz
CROSS_TGZ     := $(notdir $(CROSS_URL))
CROSS_DIR     := $(CURDIR)/$(TOOLCHAIN_NAME)
TOOLCHAIN_GCC := $(CROSS_DIR)/bin/$(TRIPLET)-gcc

LIBPCAP_VER   := 1.10.5
LIBPCAP_BASE  := libpcap-$(LIBPCAP_VER)
LIBPCAP_URL   := https://www.tcpdump.org/release/$(LIBPCAP_BASE).tar.xz
LIBPCAP_XZ    := $(notdir $(LIBPCAP_URL))
LIBPCAP_DIR   := $(CURDIR)/$(LIBPCAP_BASE)
INSTALL_DIR   := $(LIBPCAP_DIR)/install

all: toolchain libpcap setup-env zzz

toolchain: $(CROSS_TGZ) $(CROSS_DIR)
$(CROSS_TGZ):
	@echo "→ Downloading $@"
	curl -L -o $@ $(CROSS_URL)

$(CROSS_DIR):
	@echo "→ Extracting $(CROSS_TGZ)"
	tar -xzf $(CROSS_TGZ)

libpcap: $(LIBPCAP_XZ) $(LIBPCAP_DIR)
$(LIBPCAP_XZ):
	@echo "→ Downloading $@"
	curl -L -o $@ $(LIBPCAP_URL)

$(LIBPCAP_DIR):
	@echo "→ Extracting $(LIBPCAP_XZ)"
	tar -xf $(LIBPCAP_XZ)

$(INSTALL_DIR): $(LIBPCAP_DIR)
	@echo "→ Building libpcap for $(TRIPLET)"
	cd $(LIBPCAP_DIR) && \
		./configure --host=$(TRIPLET) --with-pcap=linux \
		            CC=$(TOOLCHAIN_GCC) --prefix=$(INSTALL_DIR) && \
		make -j$(shell nproc) && make install

libpcap: $(INSTALL_DIR)

zzz:
	@if [ -d zzz ]; then \
	  echo "→ Updating zzz repository"; \
	  git -C zzz pull; \
	else \
	  echo "→ Cloning zzz repository"; \
	  git clone https://github.com/diredocks/zzz.git; \
	fi
	@echo "→ Building zzz for $(TRIPLET)"
	cd zzz && \
	PKG_CONFIG_LIBDIR=$(INSTALL_DIR)/lib/pkgconfig \
	cmake -B build-$(TRIPLET) -S . -DCMAKE_C_COMPILER=$(TOOLCHAIN_GCC) && \
	cd build-$(TRIPLET) && make

clean:
	rm -rf $(CROSS_TGZ) $(CROSS_DIR) $(LIBPCAP_XZ) $(LIBPCAP_DIR) zzz
