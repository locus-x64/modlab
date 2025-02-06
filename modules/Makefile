obj-m +=netfilter_monitor.o
obj-m +=filesystem_monitor.o
all: 
	echo $(OBJECTS)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
