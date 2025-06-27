default:
	@just --list

alias s := start
start:
	DEBUG=1 PORT=5312 go run .

alias b := build
build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o doh-hole .
	strip doh-hole

alias ba := buildarm64
buildarm64:
	GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o doh-hole.arm64 .
	# strip doh-hole.arm64

alias i := install
install: build
	sudo rm -f /usr/bin/doh-hole
	sudo cp doh-hole /usr/bin/

	sudo rm -f  /etc/systemd/system/doh-hole.service
	sudo cp doh-hole.service /etc/systemd/system/

	sudo systemctl daemon-reload
	sudo systemctl enable doh-hole.service
	sudo systemctl restart doh-hole.service

	sleep 1
	sudo systemctl status doh-hole.service
	