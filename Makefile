obj-m := max44009.o
KERNEL_DIR ?=/home/bobby/Downloads/linux-kernel-labs/modules/nfsroot/root/beaglebone/linux
CROSS_COMPILE := arm-linux-gnueabi-
ARCH := arm

all: max44009.c tools
	make -C $(KERNEL_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) \
		SUBDIRS=$(PWD) modules

clean:
	make -C $(KERNEL_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) \
		SUBDIRS=$(PWD) clean


tools: write_int_time.c
	$(CROSS_COMPILE)gcc -o write_int_time $<
