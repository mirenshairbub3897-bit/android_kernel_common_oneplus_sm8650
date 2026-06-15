obj-m += bgmi_offset_checker.o

KDIR := $(shell pwd)/..

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
