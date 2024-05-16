all: user kernel

clean:
	@cargo clean

env:
	@cargo task env

kernel:
	@cargo task build kernel

user:
	@cargo task build user

.PHONY: all clean env kernel user
