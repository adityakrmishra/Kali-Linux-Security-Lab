# Kernel module specific
obj-m += advanced_rootkit_detector.o
advanced_rootkit_detector-objs := main.o crypto.o procfs.o

# Security flags
KCFLAGS += -Wall -Werror -fno-strict-aliasing

# Debug vs Release
ifdef DEBUG
KCFLAGS += -DDEBUG -g
endif

# Kernel directory handling
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
