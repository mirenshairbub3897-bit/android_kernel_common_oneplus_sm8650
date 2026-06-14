obj-m += hello.o

PWD := $(shell pwd)

# IMPORTANT: kernel identity match (OP-WILD fix)
EXTRA_CFLAGS += -DLOCALVERSION=\"-OP-WILD\"

KDIR ?= $(KERNEL_DIR)
KDIR ?= $(shell pwd)/../

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
