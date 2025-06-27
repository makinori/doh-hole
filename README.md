# DoH Hole

Tiny DNS over HTTPS resolver with block list in Go

Uses https://quad9.net and [StevenBlack/hosts](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts)

Find more in [main.go](https://github.com/makinori/doh-hole/blob/main/main.go)

## Installation

-   Make sure `/etc/resolv.conf` isn't getting overwritten

    https://wiki.archlinux.org/title/Domain_name_resolution#Overwriting_of_/etc/resolv.conf

    For **NetworkManager**, write `/etc/NetworkManager/conf.d/dns.conf`

    ```
    [main]
    dns=none
    ```

-   Build and install with `just install`<br/>
    Please read **Justfile** before running

-   Update `/etc/resolv.conf` with `nameserver 127.0.0.1`

-   Verify at https://on.quad9.net and any from [StevenBlack/hosts](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts)

## UniFi OS

-   Build with `just buildarm64` and place in `/data/doh-hole`

-   Copy `unifi-os/doh-hole.service` to `/etc/systemd/system/doh-hole.service`

-   Enable and start service

    ```bash
    systemctl daemon-reload
    systemctl enable --now doh-hole.service
    systemctl status doh-hole.service
    ```

-   Make sure encrypted DNS is disabled in settings<br/>
    and set DNS under internet to `127.0.53.54`

TODO: although it works, filtered dns replies aren't 100% correct and get dropped
