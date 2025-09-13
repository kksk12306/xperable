# SPDX-License-Identifier: GPL-3.0-or-later
#
# Makefile for xperable - Xperia ABL fastboot Exploit of CVE-2021-1931
#
# Copyright (C) 2025 j4nn at xdaforums
#


CFLAGS := -D_GNU_SOURCE -ggdb

ifneq ($(wildcard target-o77.c),)
  DEFINES += TARGET_ABL_O77
  TARGETS += target-o77.c
  DEPENDS += LinuxLoader-o77.pe
endif

ifneq ($(wildcard target-p114.c),)
  DEFINES += TARGET_ABL_P114
  TARGETS += target-p114.c
  DEPENDS += LinuxLoader-p114.pe boot/xfl-o77.mbn
endif

ifneq ($(wildcard target-p118.c),)
  DEFINES += TARGET_ABL_P118
  TARGETS += target-p118.c
  DEPENDS += LinuxLoader-p118.pe
endif

ifneq ($(wildcard target-q207.c),)
  DEFINES += TARGET_ABL_Q207
  TARGETS += target-q207.c
  DEPENDS += LinuxLoader-q207.pe
endif

ifeq ($(CROSS_BUILD),)
  CROSS_BUILD := native
  XPERABLE ?= xperable
  CC := gcc
  CXX := g++
ifneq ($(wildcard libusb-static/libusb-1.0.a),)
    LDFLAGS += -static -Llibusb-static
endif

else ifeq ($(CROSS_BUILD),mingw64)
  XPERABLE := xperable.exe
  CC := /usr/lib/mingw64-toolchain/bin/x86_64-w64-mingw32-gcc
  CXX := /usr/lib/mingw64-toolchain/bin/x86_64-w64-mingw32-g++
  PEPARSE_CMAKE_OPTS := -DCMAKE_SYSTEM_NAME=Windows \
    -DCMAKE_C_COMPILER=$(CC) \
    -DCMAKE_CXX_COMPILER=$(CXX) \
    -DCMAKE_FIND_ROOT_PATH=/usr/lib/mingw64-toolchain \
    -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY
  DEPENDS += libusb-mingw/MinGW64/static/libusb-1.0.a
  CFLAGS += -Ilibusb-mingw/include
  LDFLAGS += -Llibusb-mingw/MinGW64/static

else ifeq ($(CROSS_BUILD),aarch64)
  XPERABLE := xperable.aarch64
  CC := aarch64-unknown-linux-musl-gcc
  CXX := aarch64-unknown-linux-musl-g++
  PEPARSE_CMAKE_OPTS := -DCMAKE_SYSTEM_NAME=Linux \
    -DCMAKE_C_COMPILER=$(CC) \
    -DCMAKE_CXX_COMPILER=$(CXX) \
    -DCMAKE_FIND_ROOT_PATH=/usr/aarch64-unknown-linux-musl \
    -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY
  LDFLAGS += -static

else ifeq ($(CROSS_BUILD),x86_64)
  XPERABLE ?= xperable
  CC := x86_64-unknown-linux-musl-gcc
  CXX := x86_64-unknown-linux-musl-g++
  PEPARSE_CMAKE_OPTS := -DCMAKE_SYSTEM_NAME=Linux \
    -DCMAKE_C_COMPILER=$(CC) \
    -DCMAKE_CXX_COMPILER=$(CXX) \
    -DCMAKE_FIND_ROOT_PATH=/usr/x86_64-unknown-linux-musl \
    -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY
  LDFLAGS += -static
endif

PEPARSE_CMAKE_OPTS += -DCMAKE_BUILD_TYPE=Release \
  -DDEFAULT_CXX_FLAGS=-Wno-deprecated-declarations \
  -DCMAKE_COLOR_MAKEFILE=OFF -DCMAKE_MESSAGE_LOG_LEVEL=WARNING
LDFLAGS += -Lpe-parse/build-$(CROSS_BUILD)/pe-parser-library

all: $(XPERABLE)

boot/bootloader_X_BOOT_MSM8998_LA1_1_O_77_X-FLASH-ALL-C93B.sin:
	@if [ ! -e 47.1.A.2.281 ]; then \
		mkdir -p boot; \
		echo -e "\nDownload one of the earliest stock firmwares like 47.1.A.2.281 and copy"; \
		echo -e "  $@\nfile into the boot subdirectory here.\n"; false; \
	else unzip -q -n -d boot 47.1.A.2.281/boot.zip *-C93B.sin && chmod a-x boot/*.sin; fi

boot/bootloader_X_BOOT_MSM8998_LA2_0_P_114_X-FLASH-ALL-C93B.sin:
	@if [ ! -e 47.2.A.11.228 ]; then \
		mkdir -p boot; \
		echo -e "\nDownload the latest stock firmware like 47.2.A.11.228 and copy"; \
		echo -e "  $@\nfile into the boot subdirectory here.\n"; false; \
	else unzip -q -n -d boot 47.2.A.11.228/boot.zip *-C93B.sin; fi

boot/bootloader_X_BOOT_SDM845_LA2_0_P_118_X-FLASH-ALL-B6B5.sin:
	@if [ ! -e 52.0.A.8.50 ]; then \
		mkdir -p boot; \
		echo -e "\nDownload stock firmware 52.0.A.8.50 version and copy"; \
		echo -e "  $@\nfile into the boot subdirectory here.\n"; false; \
	else unzip -q -n -d boot 52.0.A.8.50/boot.zip *-B6B5.sin; fi

boot/bootloader_X_BOOT_SDM845_LA2_0_1_Q_207_X-FLASH-ALL-B6B5.sin:
	@if [ ! -e 52.1.A.3.49 ]; then \
		mkdir -p boot; \
		echo -e "\nDownload stock firmware 52.1.A.3.49 version and copy"; \
		echo -e "  $@\nfile into the boot subdirectory here.\n"; false; \
	else unzip -q -n -d boot 52.1.A.3.49/boot.zip *-B6B5.sin; fi

%-$(CROSS_BUILD).o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

xperable-$(CROSS_BUILD).o: xperable.c $(TARGETS) fbusb.h logging.h $(DEPENDS)
	$(CC) $(addprefix -D, $(DEFINES)) $(CFLAGS) -o $@ -c $<

$(XPERABLE): xperable-$(CROSS_BUILD).o pe-load-$(CROSS_BUILD).o fbusb-$(CROSS_BUILD).o
	$(CXX) $(CFLAGS) $(LDFLAGS) -o $@ $^ -lpe-parse -lusb-1.0

pe-load-$(CROSS_BUILD).o: pe-load.cpp pe-parse/build-$(CROSS_BUILD)/pe-parser-library/libpe-parse.a
	$(CXX) $(CFLAGS) -o $@ -c $< -Ipe-parse/pe-parser-library/include

pe-parse/CMakeLists.txt:
	if [ -d .git ]; then git submodule update --init; \
	else wget https://github.com/trailofbits/pe-parse/archive/refs/heads/master.zip \
		&& unzip -q master.zip && mv pe-parse-master pe-parse && rm -f master.zip ; \
	fi

libusb-mingw/MinGW64/static/libusb-1.0.a:
	mkdir -p libusb-mingw
	wget -P libusb-mingw https://github.com/libusb/libusb/releases/download/v1.0.29/libusb-1.0.29.7z
	7z -olibusb-mingw x libusb-mingw/libusb-1.0.29.7z MinGW64 include README.txt &>/dev/null \
		|| [ -f libusb-mingw/MinGW64/static/libusb-1.0.a -a -f libusb-mingw/include/libusb.h ]
	rm -f libusb-mingw/MinGW64/static/libusb-1.0.dll.a
	mkdir -p libusb-mingw/include/libusb-1.0
	mv libusb-mingw/include/libusb.h libusb-mingw/include/libusb-1.0

pe-parse/build-$(CROSS_BUILD)/pe-parser-library/libpe-parse.a: pe-parse/CMakeLists.txt
	mkdir -p pe-parse/build-$(CROSS_BUILD)
	(cd pe-parse/build-$(CROSS_BUILD); cmake -DBUILD_SHARED_LIBS=OFF $(PEPARSE_CMAKE_OPTS) .. && make -j4)

boot/xfl-o77.mbn: boot/bootloader_X_BOOT_MSM8998_LA1_1_O_77_X-FLASH-ALL-C93B.sin
	mkdir -p boot/bootloader-o77
	tar xf $< -C boot/bootloader-o77
	tar xf boot/bootloader-o77/bootloader.000 -C boot/bootloader-o77
	echo '41867a4f9becf0587ebc7f18aad85d70133c183c11762a93133f3ce7e29ec6b9 *boot/bootloader-o77/xfl_X_BOOT_MSM8998_LA1_1_O_77.mbn' | sha256sum -c \
	|| echo 'c745a32721d68bb7499a0e929bd9bcfec307cb922d0c17c22f064a51e6e1a7c7 *boot/bootloader-o77/xfl_X_BOOT_MSM8998_LA1_1_O_77.mbn' | sha256sum -c
	cp boot/bootloader-o77/xfl_X_BOOT_MSM8998_LA1_1_O_77.mbn $@

LinuxLoader-o77.pe: boot/xfl-o77.mbn
	uefi-firmware-parser -b -e -q -o boot/bootloader-o77/abl boot/bootloader-o77/abl_X_BOOT_MSM8998_LA1_1_O_77.mbn &>/dev/null
	cp -p `find boot/bootloader-o77/abl -name section1.pe` $@

LinuxLoader-p114.pe: boot/bootloader_X_BOOT_MSM8998_LA2_0_P_114_X-FLASH-ALL-C93B.sin
	mkdir -p boot/bootloader-p114
	tar xf $< -C boot/bootloader-p114
	tar xf boot/bootloader-p114/bootloader.000 -C boot/bootloader-p114
	uefi-firmware-parser -b -e -q -o boot/bootloader-p114/abl boot/bootloader-p114/abl_X_BOOT_MSM8998_LA2_0_P_114.mbn &>/dev/null
	cp -p `find boot/bootloader-p114/abl -name section1.pe` $@

LinuxLoader-p118.pe: boot/bootloader_X_BOOT_SDM845_LA2_0_P_118_X-FLASH-ALL-B6B5.sin
	mkdir -p boot/bootloader-p118
	tar xf $< -C boot/bootloader-p118
	tar xf boot/bootloader-p118/bootloader.000 -C boot/bootloader-p118
	uefi-firmware-parser -b -e -q -o boot/bootloader-p118/abl boot/bootloader-p118/abl_X_BOOT_SDM845_LA2_0_P_118.mbn &>/dev/null
	cp -p `find boot/bootloader-p118/abl -name section1.pe` $@

LinuxLoader-q207.pe: boot/bootloader_X_BOOT_SDM845_LA2_0_1_Q_207_X-FLASH-ALL-B6B5.sin
	mkdir -p boot/bootloader-q207
	tar xf $< -C boot/bootloader-q207
	tar xf boot/bootloader-q207/bootloader.000 -C boot/bootloader-q207
	uefi-firmware-parser -b -e -q -o boot/bootloader-q207/abl boot/bootloader-q207/abl_X_BOOT_SDM845_LA2_0_1_Q_207.mbn &>/dev/null
	cp -p `find boot/bootloader-q207/abl -name section1.pe` $@

clean:
	rm -rf *-$(CROSS_BUILD).o pe-parse/build-$(CROSS_BUILD)
	rm -rf boot/bootloader-o77 boot/bootloader-p114 boot/bootloader-p118 boot/bootloader-q207

distclean: clean
	rm -rf pe-parse/build-*
	rm -f *.o
	rm -f xperable xperable.native xperable.x86_64 xperable.exe xperable.aarch64
	rm -f LinuxLoader-o77.pe LinuxLoader-p114.pe LinuxLoader-p118.pe LinuxLoader-q207.pe boot/xfl-o77.mbn

fullclean: distclean
	rm -rf pe-parse
	rm -rf libusb-mingw
	rm -rf boot
