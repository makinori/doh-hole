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
	sudo rm -f /usr/bin/doh-hole
	sudo cp doh-hole /usr/bin/

	sudo rm -f  /etc/systemd/system/doh-hole.service
	sudo cp doh-hole.service /etc/systemd/system/

	sudo systemctl daemon-reload
	sudo systemctl enable --now doh-hole.service

	sleep 1
	sudo systemctl status doh-hole.service

	sudo rm -f /etc/resolv.conf
	sudo bash -c "echo 'nameserver 127.0.0.1' > /etc/resolv.conf" 
