obj-m := max44009.o
KERNEL_DIR ?= $(HOME)/git/kernels/arm/staging
IP := 192.168.0.100

all:
	make -C $(KERNEL_DIR) ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- \
		SUBDIRS=$(PWD) modules

clean:
	make -C $(KERNEL_DIR) ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- \
		SUBDIRS=$(PWD) clean

deploy:
	scp *.ko ubuntu@$(IP):
