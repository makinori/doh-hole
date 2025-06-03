default:
	@just --list

alias s := start
start:
	DEBUG=1 PORT=5312 go run .

alias b := build
build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o doh-hole .
	strip doh-hole

alias i := install
install: build
	sudo cp doh-hole /usr/bin
