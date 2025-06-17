.PHONY: all toolchain libpcap zzz clean

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
$(error Unsupported ARCH '$(ARCH)'. Supported: armv7 aarch64 x86_64 i686 mips64 mipsel riscv64)
endif

DEPS_DIR       := $(CURDIR)/deps
TRIPLET        := $(patsubst %-cross,%,$(TOOLCHAIN_NAME))
CROSS_URL      := https://musl.cc/$(TOOLCHAIN_NAME).tgz
CROSS_TGZ      := $(DEPS_DIR)/$(notdir $(CROSS_URL))
CROSS_DIR      := $(DEPS_DIR)/$(TOOLCHAIN_NAME)
TOOLCHAIN_GCC  := $(CROSS_DIR)/bin/$(TRIPLET)-gcc

LIBPCAP_VER    := 1.10.5
LIBPCAP_BASE   := libpcap-$(LIBPCAP_VER)
LIBPCAP_URL    := https://www.tcpdump.org/release/$(LIBPCAP_BASE).tar.xz
LIBPCAP_XZ     := $(DEPS_DIR)/$(notdir $(LIBPCAP_URL))
LIBPCAP_DIR    := $(DEPS_DIR)/$(LIBPCAP_BASE)
INSTALL_DIR    := $(LIBPCAP_DIR)/install

all: toolchain libpcap zzz

$(DEPS_DIR):
	@mkdir -p $@

$(CROSS_TGZ): | $(DEPS_DIR)
	@echo "→ Downloading $(notdir $@)"
	curl -L -o $@ $(CROSS_URL)

$(CROSS_DIR): $(CROSS_TGZ)
	@echo "→ Extracting $(notdir $(CROSS_TGZ)) to $(DEPS_DIR)"
	tar -xzf $(CROSS_TGZ) -C $(DEPS_DIR)

toolchain: $(CROSS_TGZ) $(CROSS_DIR)

$(LIBPCAP_XZ): | $(DEPS_DIR)
	@echo "→ Downloading $(notdir $@)"
	curl -L -o $@ $(LIBPCAP_URL)

$(LIBPCAP_DIR): $(LIBPCAP_XZ)
	@echo "→ Extracting $(notdir $(LIBPCAP_XZ))"
	tar -xf $(LIBPCAP_XZ) -C $(DEPS_DIR)

$(INSTALL_DIR): $(LIBPCAP_DIR)
	@echo "→ Building libpcap for $(TRIPLET)"
	cd $(LIBPCAP_DIR) && \
		./configure --host=$(TRIPLET) --with-pcap=linux \
		            CC=$(TOOLCHAIN_GCC) --prefix=$(INSTALL_DIR) && \
		make -j$(shell nproc) && make install

libpcap: $(INSTALL_DIR)

zzz:
	@echo "→ Building zzz for $(TRIPLET)"
	PKG_CONFIG_LIBDIR=$(INSTALL_DIR)/lib/pkgconfig \
	cmake -B build-$(TRIPLET) -S . -DCMAKE_C_COMPILER=$(TOOLCHAIN_GCC) && \
	cd build-$(TRIPLET) && make

clean:
	rm -rf $(DEPS_DIR) $(LIBPCAP_DIR) build-$(TRIPLET)
