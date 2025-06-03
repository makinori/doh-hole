# DoH Hole

Tiny DNS over HTTPS resolver with block list in Go

Uses [dns.sb](https://dns.sb) and [StevenBlack/hosts](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts)

Find more in `main.go`

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

-   Verify at top of https://dns.sb and any from [StevenBlack/hosts](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts)
