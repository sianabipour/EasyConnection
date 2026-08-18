FROM alpine:3.20

RUN apk add --no-cache openssh-server \
 && ssh-keygen -A \
 && adduser -D -s /bin/sh tunnel \
 && echo "tunnel:tunnelpass" | chpasswd \
 && mkdir -p /var/run/sshd \
 && printf '%s\n' \
      'PasswordAuthentication yes' \
      'PermitRootLogin no' \
      'AllowTcpForwarding yes' \
      'PermitOpen any' \
      'GatewayPorts no' \
      'Subsystem sftp /usr/lib/ssh/sftp-server' \
      > /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
