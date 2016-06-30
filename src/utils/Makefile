#!/usr/bin/make -f

all: generate_key read_directory

generate_key:
	go build -o $(BINDIR)/generate_key generate_key.go

read_directory:
	go build -o $(BINDIR)/read_directory read_directory.go

.PHONY: generate_key read_directory
