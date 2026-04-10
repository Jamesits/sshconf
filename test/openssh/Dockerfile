FROM alpine:latest

# Install OpenSSH server and minimal web server for port forwarding tests
RUN apk add --no-cache \
    openssh-server \
    openssh-client \
    openssh-sftp-server \
    python3 \
    curl \
    socat \
    bash

# Generate host keys
RUN ssh-keygen -A

# Create test user with known password
RUN adduser -D -s /bin/bash testuser && \
    echo "testuser:testpass" | chpasswd

# Set up SSH directory for test user
RUN mkdir -p /home/testuser/.ssh && \
    chmod 700 /home/testuser/.ssh && \
    chown testuser:testuser /home/testuser/.ssh

# Generate a test keypair (will be volume-mounted or copied by test script)
RUN ssh-keygen -t ed25519 -f /etc/ssh/test_key -N "" && \
    cp /etc/ssh/test_key.pub /home/testuser/.ssh/authorized_keys && \
    chmod 600 /home/testuser/.ssh/authorized_keys && \
    chown testuser:testuser /home/testuser/.ssh/authorized_keys

# Configure sshd
RUN cat > /etc/ssh/sshd_config <<'EOF'
Port 22
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::

# Host keys
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_rsa_key

# Authentication
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
KbdInteractiveAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# Allow environment variables for SetEnv/SendEnv tests
AcceptEnv LANG LC_* TEST_*

# Allow agent forwarding
AllowAgentForwarding yes

# Allow TCP forwarding for port forwarding tests
AllowTcpForwarding yes
GatewayPorts clientspecified
PermitTunnel yes

# Subsystems
Subsystem sftp /usr/lib/ssh/sftp-server

# Logging
LogLevel VERBOSE

# Banner for banner callback test
Banner /etc/ssh/banner.txt
EOF

# Create banner
RUN echo "=== Test SSH Server ===" > /etc/ssh/banner.txt

# Create a simple web server script for port forwarding tests
RUN cat > /usr/local/bin/webserver.sh <<'SCRIPT'
#!/bin/bash
# Minimal HTTP server using socat
PORT=${1:-8080}
RESPONSE="HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nhello from port $PORT"
exec socat TCP-LISTEN:$PORT,fork,reuseaddr SYSTEM:"echo -e '$RESPONSE'"
SCRIPT
RUN chmod +x /usr/local/bin/webserver.sh

# Entrypoint: start web server in background, then sshd in foreground
RUN cat > /entrypoint.sh <<'SCRIPT'
#!/bin/bash
set -e

# Start web server on port 8080 for forwarding tests
/usr/local/bin/webserver.sh 8080 &

# Start web server on port 8081 as a second target
/usr/local/bin/webserver.sh 8081 &

# Start sshd in foreground
exec /usr/sbin/sshd -D -e
SCRIPT
RUN chmod +x /entrypoint.sh

EXPOSE 22 8080 8081

CMD ["/entrypoint.sh"]
