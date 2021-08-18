# srcds-hardening-iptables-docker
Smallish script to prevent smallish A2S attacks with source engine servers. Supports servers running on docker (using the `DOCKER-USER` chain) and on bare metal/tmux/etc (using the `INPUT` chain). Vaguely adapted from https://forums.alliedmods.net/showthread.php?t=151551.

# Trusted Hosts
Under `/etc/hosts.trusted`, to allow a list of hosts unbridled access to your servers, you can create a file called `/etc/hosts.trusted` and add a list of IPs you trust separated by a newline.

Example of such a file:
```
192.168.0.1/24
10.0.12.1/24
```

