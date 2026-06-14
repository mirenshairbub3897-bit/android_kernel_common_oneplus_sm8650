obj-m += hello.o

# kernel build system (important for GitHub Actions)
KDIR ?= $(PWD)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
