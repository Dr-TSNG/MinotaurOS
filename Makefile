BOARD ?= qemu

clean:
	@cargo clean

env:
	@cargo task env

kernel:
	@cargo task build kernel --board $(BOARD)

debug:
	@cargo task debug qemu

all: kernel

.PHONY: clean env kernel qemu all
