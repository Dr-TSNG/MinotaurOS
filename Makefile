BOARD ?= qemu

clean:
	@cargo clean

env:
	@cargo task env

kernel:
	@cargo task build kernel --board $(BOARD)

bootloader:
	@cargo task build bootloader --board $(BOARD)

qemu:
	@cargo task run qemu

all: bootloader

.PHONY: clean env kernel bootloader qemu all
