#
# Makefile for TOA module.
#


#obj-$(CONFIG_TOA) += toa.o
obj-m += toa.o
all:
	make -C /lib/modules/`uname -r`/build M=$(PWD)
	#make -C /lib/modules/`uname -r`/build SUBDIRS=$(PWD) modules
clean:
	make -C /lib/modules/`uname -r`/build M=$(PWD) clean
	#make -C /lib/modules/`uname -r`/build SUBDIRS=$(PWD) clean

