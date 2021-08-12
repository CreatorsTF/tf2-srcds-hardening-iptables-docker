# srcds-hardening-iptables-docker
Small script to prevent smallish A2S attacks with source engine servers. Supports servers running on docker (using the `DOCKER-USER` chain) and on bare metal/tmux/etc (using the `INPUT` chain). Vaguely adapted from https://forums.alliedmods.net/showthread.php?t=151551.
