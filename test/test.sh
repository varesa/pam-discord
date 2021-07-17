#!/usr/bin/env bash
set -euo pipefail

podman build -t pamtest test/
podman run --rm -ti --name pamtest \
    -v $PWD/target/debug/libpam_discord.so:/usr/lib64/security/pam_discord.so \
    -v $PWD/conf/sshd:/etc/pam.d/sshd \
    -v $PWD/conf/sshd_config:/etc/ssh/sshd_config \
    -v $PWD/conf/discord-url:/etc/discord-url \
    -p 2222:22 --privileged pamtest
