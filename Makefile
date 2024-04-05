BOARD ?= qemu

clean:
	@cargo clean

env:
	@cargo task env

kernel:
	@cargo task build kernel --board $(BOARD)

user:
	@cargo task build user

debug:
	@cargo task debug qemu

all: user kernel

.PHONY: clean env kernel user qemu all
