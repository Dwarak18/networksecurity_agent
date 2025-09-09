#!/bin/bash
# Network Security Agent Installation Script
# Installs and configures the security agent as a system service

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/security-agent"
SERVICE_NAME="security-agent"
USER_NAME="security-agent"
GROUP_NAME="security-agent"
LOG_DIR="/var/log/security-agent"
CONFIG_DIR="$INSTALL_DIR/config"

echo -e "${BLUE}🛡️  Network Security Agent Installation${NC}"
echo "=========================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Detect OS
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS=$NAME
    VERSION=$VERSION_ID
else
    echo -e "${RED}Cannot detect OS. This script supports Ubuntu/Debian and CentOS/RHEL.${NC}"
    exit 1
fi

echo -e "${GREEN}Detected OS: $OS $VERSION${NC}"

# Install system dependencies
echo -e "${YELLOW}Installing system dependencies...${NC}"

if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
    apt-get update
    apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        libpcap-dev \
        nftables \
        iptables \
        ipset \
        curl \
        wget \
        systemd \
        build-essential
        
elif [[ "$OS" == *"CentOS"* ]] || [[ "$OS" == *"Red Hat"* ]] || [[ "$OS" == *"Rocky"* ]]; then
    yum update -y
    yum install -y \
        python3 \
        python3-pip \
        libpcap-devel \
        nftables \
        iptables \
        ipset \
        curl \
        wget \
        systemd \
        gcc \
        gcc-c++ \
        make
        
else
    echo -e "${RED}Unsupported OS: $OS${NC}"
    exit 1
fi

# Create user and group
echo -e "${YELLOW}Creating security agent user...${NC}"
if ! id "$USER_NAME" &>/dev/null; then
    groupadd -r "$GROUP_NAME"
    useradd -r -g "$GROUP_NAME" -d "$INSTALL_DIR" -s /usr/sbin/nologin \
        -c "Network Security Agent" "$USER_NAME"
    echo -e "${GREEN}Created user: $USER_NAME${NC}"
else
    echo -e "${YELLOW}User $USER_NAME already exists${NC}"
fi

# Create directories
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p "$INSTALL_DIR"/{src,config,data,logs}
mkdir -p "$LOG_DIR"
mkdir -p /etc/security-agent

# Set permissions
chown -R "$USER_NAME":"$GROUP_NAME" "$INSTALL_DIR"
chown -R "$USER_NAME":"$GROUP_NAME" "$LOG_DIR"
chmod 755 "$INSTALL_DIR"
chmod 755 "$LOG_DIR"

# Copy application files
echo -e "${YELLOW}Installing application files...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cp -r "$PROJECT_ROOT/src"/* "$INSTALL_DIR/src/"
cp -r "$PROJECT_ROOT/config"/* "$INSTALL_DIR/config/"

# Make scripts executable
chmod +x "$INSTALL_DIR/src"/*.py

# Create Python virtual environment
echo -e "${YELLOW}Setting up Python virtual environment...${NC}"
python3 -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"

# Install Python dependencies
pip install --upgrade pip
pip install -r "$PROJECT_ROOT/requirements.txt"

# Set ownership
chown -R "$USER_NAME":"$GROUP_NAME" "$INSTALL_DIR"

# Install systemd service
echo -e "${YELLOW}Installing systemd service...${NC}"
cp "$PROJECT_ROOT/deploy/security-agent.service" "/etc/systemd/system/"
systemctl daemon-reload

# Configure firewall
echo -e "${YELLOW}Configuring firewall...${NC}"

# Enable nftables service
systemctl enable nftables
systemctl start nftables

# Create basic nftables configuration if it doesn't exist
if [ ! -f /etc/nftables.conf ] || [ ! -s /etc/nftables.conf ]; then
    cat > /etc/nftables.conf << 'EOF'
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy accept;
        ct state invalid drop
        ct state {established, related} accept
        iif lo accept
        ip protocol icmp accept
        ip6 nexthdr ipv6-icmp accept
        tcp dport ssh accept
    }
    
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF
    
    # Reload nftables
    nft -f /etc/nftables.conf
fi

# Configure log rotation
echo -e "${YELLOW}Configuring log rotation...${NC}"
cat > /etc/logrotate.d/security-agent << 'EOF'
/var/log/security-agent/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 security-agent security-agent
    postrotate
        systemctl reload security-agent || true
    endscript
}
EOF

# Create default configuration
echo -e "${YELLOW}Creating default configuration...${NC}"
if [ ! -f "$CONFIG_DIR/security_agent.yaml" ]; then
    # Use the default config
    echo -e "${GREEN}Using default configuration${NC}"
else
    echo -e "${YELLOW}Configuration already exists, keeping current settings${NC}"
fi

# Set capabilities for the Python binary
echo -e "${YELLOW}Setting capabilities for packet capture...${NC}"
setcap cap_net_raw,cap_net_admin+eip "$INSTALL_DIR/venv/bin/python3"

# Enable and start service
echo -e "${YELLOW}Enabling and starting service...${NC}"
systemctl enable "$SERVICE_NAME"

# Test configuration
echo -e "${YELLOW}Testing configuration...${NC}"
if sudo -u "$USER_NAME" "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/src/security_agent.py" --config "$CONFIG_DIR/security_agent.yaml" --test; then
    echo -e "${GREEN}Configuration test passed${NC}"
else
    echo -e "${RED}Configuration test failed. Please check the logs.${NC}"
    exit 1
fi

# Start the service
systemctl start "$SERVICE_NAME"

# Check service status
sleep 2
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo -e "${GREEN}✅ Service started successfully${NC}"
else
    echo -e "${RED}❌ Service failed to start. Check logs with: journalctl -u $SERVICE_NAME${NC}"
    exit 1
fi

# Create CLI wrapper script
echo -e "${YELLOW}Creating CLI wrapper...${NC}"
cat > /usr/local/bin/security-agent << EOF
#!/bin/bash
# Network Security Agent CLI wrapper

INSTALL_DIR="$INSTALL_DIR"
PYTHON="\$INSTALL_DIR/venv/bin/python"
AGENT_SCRIPT="\$INSTALL_DIR/src/security_agent.py"
CONFIG="\$INSTALL_DIR/config/security_agent.yaml"

case "\$1" in
    status)
        systemctl status $SERVICE_NAME
        ;;
    start)
        systemctl start $SERVICE_NAME
        ;;
    stop)
        systemctl stop $SERVICE_NAME
        ;;
    restart)
        systemctl restart $SERVICE_NAME
        ;;
    reload)
        systemctl reload $SERVICE_NAME
        ;;
    logs)
        journalctl -u $SERVICE_NAME -f
        ;;
    config)
        \$EDITOR "\$CONFIG"
        ;;
    test)
        sudo -u $USER_NAME "\$PYTHON" "\$AGENT_SCRIPT" --config "\$CONFIG" --test
        ;;
    block)
        if [ -z "\$2" ]; then
            echo "Usage: security-agent block <ip>"
            exit 1
        fi
        curl -X POST http://localhost:8080/api/v1/blocklist \\
             -H "Content-Type: application/json" \\
             -d "{\"ip\":\"\$2\",\"reason\":\"Manual CLI block\"}"
        ;;
    unblock)
        if [ -z "\$2" ]; then
            echo "Usage: security-agent unblock <ip>"
            exit 1
        fi
        curl -X DELETE "http://localhost:8080/api/v1/blocklist?ip=\$2"
        ;;
    blocklist)
        curl -s http://localhost:8080/api/v1/blocklist | python3 -m json.tool
        ;;
    stats)
        curl -s http://localhost:8080/api/v1/stats | python3 -m json.tool
        ;;
    *)
        echo "Network Security Agent CLI"
        echo "Usage: security-agent {status|start|stop|restart|reload|logs|config|test|block|unblock|blocklist|stats}"
        echo ""
        echo "Commands:"
        echo "  status    - Show service status"
        echo "  start     - Start the service"
        echo "  stop      - Stop the service"
        echo "  restart   - Restart the service"
        echo "  reload    - Reload configuration"
        echo "  logs      - Show live logs"
        echo "  config    - Edit configuration"
        echo "  test      - Test configuration"
        echo "  block     - Block an IP address"
        echo "  unblock   - Unblock an IP address"
        echo "  blocklist - Show blocked IPs"
        echo "  stats     - Show statistics"
        ;;
esac
EOF

chmod +x /usr/local/bin/security-agent

# Display installation summary
echo ""
echo -e "${GREEN}🎉 Installation completed successfully!${NC}"
echo "=========================================="
echo -e "${BLUE}Installation directory:${NC} $INSTALL_DIR"
echo -e "${BLUE}Configuration file:${NC} $CONFIG_DIR/security_agent.yaml"
echo -e "${BLUE}Log directory:${NC} $LOG_DIR"
echo -e "${BLUE}Service name:${NC} $SERVICE_NAME"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Review and customize the configuration:"
echo "   sudo security-agent config"
echo ""
echo "2. Check service status:"
echo "   sudo security-agent status"
echo ""
echo "3. View live logs:"
echo "   sudo security-agent logs"
echo ""
echo "4. Access web interface:"
echo "   http://localhost:8080/status"
echo ""
echo "5. View metrics:"
echo "   http://localhost:9090/metrics"
echo ""
echo -e "${GREEN}The Network Security Agent is now protecting your system!${NC}"

# Final service status
echo ""
echo -e "${BLUE}Current service status:${NC}"
systemctl status "$SERVICE_NAME" --no-pager -l
