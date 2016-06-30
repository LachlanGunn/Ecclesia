#!/usr/bin/make -f

export BINDIR := $(PWD)/bin
SRCDIR=$(PWD)/src
export GOPATH := $(GOPATH):$(PWD)

all:
	echo $(GOPATH)
	$(MAKE) -C $(SRCDIR)

.PHONY: all
