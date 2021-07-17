FROM fedora

# Insecure / bad practice to include SSH host keys in the image, though for
# development purposes it does not matter much. Fixed keys that do not change
# over rebuilds/restarts could even be considered a plus

RUN dnf install -y openssh-server && \
    ssh-keygen -q -t rsa     -f "/etc/ssh/ssh_host_rsa_key"     -C '' -N '' && \
    ssh-keygen -q -t ecdsa   -f "/etc/ssh/ssh_host_ecdsa_key"   -C '' -N '' && \
    ssh-keygen -q -t ed25519 -f "/etc/ssh/ssh_host_ed25519_key" -C '' -N '' && \
    useradd user

CMD ["/usr/sbin/sshd", "-d"]
