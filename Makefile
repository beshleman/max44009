obj-m := max44009.o
KERNEL_DIR ?=/home/bobby/projects/kernels/linux-dev/KERNEL
CROSS_COMPILE := arm-linux-gnueabi-
ARCH := arm

all: max44009.c tools
	make -C $(KERNEL_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) \
		M=$(PWD) modules

clean:
	make -C $(KERNEL_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) \
		M=$(PWD) clean

deploy:
	scp max44009.ko debian@192.168.0.100:

tools: write_int_time.c
	$(CROSS_COMPILE)gcc -o write_int_time $<
