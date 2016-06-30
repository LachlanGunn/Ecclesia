#!/usr/bin/make -f

export BINDIR := $(PWD)/bin
SRCDIR=$(PWD)/src
export GOPATH := $(GOPATH):$(PWD)

all: bin
	echo $(GOPATH)
	$(MAKE) -C $(SRCDIR)

bin:
	mkdir -p bin

.PHONY: all
