BOARD ?= qemu

clean:
	@cargo clean

env:
	@cargo task env

kernel:
	@cargo task build kernel --board $(BOARD)

bootloader:
	@cargo task build bootloader --board $(BOARD)

debug:
	@cargo task debug qemu

all: bootloader

.PHONY: clean env kernel bootloader qemu all
