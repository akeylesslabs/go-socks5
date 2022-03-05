#!/bin/bash

export CGO_ENABLED=0
export GOOS=linux
go build -a -installsuffix cgo -ldflags '-s' && go build -a -installsuffix cgo -ldflags '-s' -o socks5-server main/main.go
#go build && go build -o socks5-server main/main.go

