# Network Security Agent 🛡️

A real-time network security monitoring and automated threat response system that captures network traffic, analyzes it for malicious patterns, and automatically blocks suspicious IPs using system firewalls.

## 🎯 Features

### Real-Time Traffic Analysis
- **Packet Capture**: Raw network traffic capture using libpcap/scapy
- **Protocol Support**: TCP, UDP, ICMP, HTTP/HTTPS analysis
- **High Performance**: Efficient packet processing with minimal latency
- **Multi-Interface**: Support for multiple network interfaces

### Advanced Threat Detection
- **SYN Flood Detection**: Identifies TCP SYN flood attacks
- **UDP Flood Detection**: Detects UDP-based DDoS attacks  
- **ICMP Flood Detection**: Monitors for ICMP ping floods
- **Port Scan Detection**: Identifies network reconnaissance attempts
- **HTTP Request Floods**: Detects application-layer DDoS
- **DNS Amplification**: Identifies DNS amplification attacks
- **Anomaly Detection**: Statistical analysis using EWMA and Z-scores
- **Threat Intelligence**: Integration with external threat feeds

### Automated Response
- **Firewall Integration**: nftables and iptables support
- **Automatic Blocking**: Real-time IP blocking with configurable TTLs
- **Rate Limiting**: Traffic shaping for suspicious sources
- **Allowlist/Denylist**: Flexible access control policies
- **Temporary Bans**: Time-based blocking with automatic expiration

### Observability & Management
- **REST API**: Full management and monitoring API
- **Prometheus Metrics**: Built-in metrics export
- **Structured Logging**: JSON and text log formats
- **Real-time Dashboard**: Web-based monitoring interface
- **CLI Management**: Command-line administration tools

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Packet Capture │ -> │ Detection Engine │ -> │ Decision Engine │
│                 │    │                  │    │                 │
│ • libpcap/scapy │    │ • Pattern Match  │    │ • Scoring       │
│ • Multi-thread  │    │ • Anomaly Detect │    │ • Access Control│
│ • Ring Buffers  │    │ • MITRE ATT&CK   │    │ • Firewall Mgmt │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         v                       v                       v
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Traffic Storage │    │ Threat Database  │    │ Action Logs     │
│                 │    │                  │    │                 │
│ • Per-IP Stats  │    │ • Detection Sigs │    │ • Block History │
│ • Sliding Window│    │ • Threat Intel   │    │ • Audit Trail   │
│ • LRU Cache     │    │ • ML Models      │    │ • Metrics       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Linux system (Ubuntu 20.04+, CentOS 8+, or similar)
- Python 3.8+
- Root privileges for packet capture and firewall management
- Network interface access

### Installation

#### Option 1: Automated Installation (Recommended)
```bash
# Download and run the installation script
curl -sSL https://raw.githubusercontent.com/your-org/network-security-agent/main/scripts/install.sh | sudo bash

# Or clone and install locally
git clone https://github.com/your-org/network-security-agent.git
cd network-security-agent
sudo ./scripts/install.sh
```

#### Option 2: Docker Deployment
```bash
# Clone the repository
git clone https://github.com/your-org/network-security-agent.git
cd network-security-agent

# Deploy with Docker Compose
docker-compose -f deploy/docker-compose.yml up -d

# Check status
docker-compose -f deploy/docker-compose.yml logs -f security-agent
```

#### Option 3: Manual Installation
```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-pip libpcap-dev nftables

# Clone repository
git clone https://github.com/your-org/network-security-agent.git
cd network-security-agent

# Install Python dependencies
pip3 install -r requirements.txt

# Configure and run
cp config/security_agent.yaml /etc/security-agent/
python3 src/security_agent.py --config /etc/security-agent/security_agent.yaml
```

### Configuration

Edit the main configuration file:
```bash
sudo security-agent config
# or
sudo nano /opt/security-agent/config/security_agent.yaml
```

Key configuration sections:
- **Network Interface**: Set the interface to monitor
- **Detection Thresholds**: Adjust sensitivity for different attack types  
- **Blocking Policies**: Configure TTLs and response actions
- **Access Control**: Define allowlists and denylists
- **Logging & Metrics**: Set up observability

### Basic Usage

```bash
# Check service status
sudo security-agent status

# View live logs
sudo security-agent logs

# Show blocked IPs
sudo security-agent blocklist

# Block an IP manually
sudo security-agent block 192.168.1.100

# Unblock an IP
sudo security-agent unblock 192.168.1.100

# View statistics
sudo security-agent stats

# Test configuration
sudo security-agent test
```

## 🔧 Configuration Reference

### Detection Thresholds

```yaml
detection:
  syn_flood:
    enabled: true
    syn_rate_threshold: 200      # SYN packets per second
    syn_ack_ratio_threshold: 0.2 # Minimum SYN/ACK ratio
    window_size: 10              # Analysis window (seconds)
    
  udp_flood:
    enabled: true
    udp_pps_threshold: 5000      # UDP packets per second
    window_size: 10
    
  port_scan:
    enabled: true
    unique_ports_threshold: 100  # Unique destination ports
    window_size: 60              # Analysis window (seconds)
```

### Scoring and Actions

```yaml
scoring:
  weights:
    syn_flood: 30
    udp_flood: 25
    port_scan: 35
    http_flood: 25
    
  thresholds:
    warn_threshold: 50           # Warning threshold
    ban_threshold: 80            # Automatic ban threshold

blocking:
  ttl:
    default: 1200               # Default block duration (20 minutes)
    port_scan: 3600            # Port scan block duration (1 hour)
    dos_attack: 7200           # DoS attack block duration (2 hours)
```

### Access Control

```yaml
access_control:
  allowlist:
    - "127.0.0.1/32"
    - "10.0.0.0/8"
    - "192.168.0.0/16"
    
  denylist:
    - "192.168.1.100/32"
    
  threat_intel:
    enabled: true
    feeds:
      - url: "https://example.com/malicious-ips.txt"
        format: "text"
        update_interval: 3600
```

## 🌐 API Reference

The security agent provides a REST API for management and monitoring:

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/status` | Agent status and health |
| GET | `/api/v1/metrics` | Metrics in JSON format |
| GET | `/api/v1/blocklist` | List blocked IPs |
| POST | `/api/v1/blocklist` | Block an IP address |
| DELETE | `/api/v1/blocklist?ip=<ip>` | Unblock an IP address |
| GET | `/api/v1/stats` | Comprehensive statistics |
| POST | `/api/v1/config` | Reload configuration |

### Examples

**Check Status:**
```bash
curl http://localhost:8080/status
```

**Block an IP:**
```bash
curl -X POST http://localhost:8080/api/v1/blocklist \
     -H "Content-Type: application/json" \
     -d '{"ip":"192.168.1.100","reason":"Manual block","ttl":3600}'
```

**View Blocked IPs:**
```bash
curl http://localhost:8080/api/v1/blocklist | jq
```

**Get Metrics:**
```bash
curl http://localhost:8080/api/v1/metrics | jq
```

## 📊 Monitoring & Metrics

### Prometheus Metrics

The agent exports metrics in Prometheus format at `http://localhost:9090/metrics`:

- `security_agent_packets_total` - Total packets processed
- `security_agent_detections_total` - Total detections made
- `security_agent_blocks_total` - Total IP blocks applied
- `security_agent_active_blocks` - Current active blocks
- `security_agent_detection_latency_ms` - Average detection latency

### Grafana Dashboard

A pre-configured Grafana dashboard is available in the `monitoring/` directory:

1. Import the dashboard: `monitoring/grafana/dashboards/security-agent.json`
2. Configure the Prometheus datasource
3. View real-time security metrics and alerts

### Log Analysis

Structured JSON logs are written to `/var/log/security-agent/agent.log`:

```json
{
  "timestamp": "2025-09-09T12:00:00Z",
  "level": "WARNING",
  "event_type": "ip_blocked",
  "ip": "192.168.1.100",
  "reason": "SYN_FLOOD (score: 85.0)",
  "ttl": 3600,
  "source_file": "decision_engine.py"
}
```

## 🧪 Testing

### Unit Tests
```bash
# Run the complete test suite
cd network-security-agent
python -m pytest tests/ -v

# Run specific test categories
python -m pytest tests/test_detection.py -v
python -m pytest tests/test_firewall.py -v
```

### Synthetic Traffic Testing
```bash
# Test SYN flood detection with hping3
sudo hping3 -S -p 80 --flood target_ip

# Test port scan detection with nmap
nmap -sS -p 1-1000 target_ip

# Test UDP flood with hping3
sudo hping3 -2 -p 53 --flood target_ip

# Test with pcap replay
tcpreplay -i eth0 test_traffic.pcap
```

### Performance Testing
```bash
# Stress test with high packet rates
python tests/performance_test.py --packets 100000 --rate 10000

# Memory usage profiling
python -m memory_profiler src/security_agent.py --test

# CPU profiling
python -m cProfile src/security_agent.py --test > profile.txt
```

## 🔒 Security Considerations

### Deployment Security
- **Principle of Least Privilege**: Run with minimal required permissions
- **Network Segmentation**: Deploy in a dedicated security network segment
- **Access Control**: Restrict API access to authorized management networks
- **Log Security**: Protect log files from tampering and unauthorized access

### Detection Accuracy
- **False Positives**: Monitor and tune thresholds to minimize false positives
- **Allowlisting**: Carefully configure allowlists for legitimate traffic
- **Baseline Training**: Allow time for anomaly detection to establish baselines
- **Threat Intelligence**: Use reputable threat feeds and validate sources

### Performance Impact
- **Resource Monitoring**: Monitor CPU and memory usage during peak traffic
- **Interface Selection**: Use dedicated monitoring interfaces when possible
- **Packet Sampling**: Consider packet sampling for very high-speed networks
- **Storage Management**: Implement log rotation and data retention policies

## 🚀 Production Deployment

### System Requirements

**Minimum:**
- 2 CPU cores
- 4GB RAM
- 20GB storage
- 1Gbps network interface

**Recommended:**
- 4+ CPU cores  
- 8GB+ RAM
- 100GB+ SSD storage
- 10Gbps+ network interface

### High Availability Setup

```yaml
# Load balancer configuration
upstream security_agents {
    server 10.0.1.10:8080;
    server 10.0.1.11:8080;
    server 10.0.1.12:8080;
}

# Shared storage for coordination
redis:
  cluster:
    enabled: true
    nodes:
      - 10.0.1.20:6379
      - 10.0.1.21:6379
      - 10.0.1.22:6379
```

### Monitoring Integration

```yaml
# Prometheus configuration
scrape_configs:
  - job_name: 'security-agent'
    static_configs:
      - targets: ['10.0.1.10:9090', '10.0.1.11:9090']
    scrape_interval: 15s

# Alerting rules
- alert: SecurityAgentDown
  expr: up{job="security-agent"} == 0
  for: 5m
  
- alert: HighThreatDetectionRate
  expr: rate(security_agent_detections_total[5m]) > 10
  for: 2m
```

## 🛠️ Development

### Project Structure
```
network-security-agent/
├── src/                     # Source code
│   ├── security_agent.py    # Main application
│   ├── packet_capture.py    # Packet capture engine
│   ├── detection_modules.py # Threat detection logic
│   ├── decision_engine.py   # Response decision making
│   ├── metrics_collector.py # Metrics and monitoring
│   └── api_server.py        # REST API server
├── config/                  # Configuration files
│   └── security_agent.yaml  # Main configuration
├── tests/                   # Test suite
│   └── test_security_agent.py
├── deploy/                  # Deployment configurations
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── security-agent.service
├── scripts/                 # Installation and utility scripts
│   └── install.sh
├── monitoring/              # Monitoring configurations
│   ├── prometheus.yml
│   └── grafana/
└── docs/                   # Documentation
```

### Contributing

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/new-detection`
3. **Write tests**: Add comprehensive tests for new functionality
4. **Follow code style**: Use black, flake8, and mypy for code quality
5. **Submit a pull request**: Include detailed description and test results

### Coding Standards

```bash
# Format code
black src/ tests/

# Check linting
flake8 src/ tests/

# Type checking
mypy src/

# Run tests
pytest tests/ --cov=src/
```

## 📚 Advanced Topics

### Custom Detection Modules

Create custom detection modules by extending the `BaseDetectionModule` class:

```python
from detection_modules import BaseDetectionModule, DetectionResult

class CustomDetector(BaseDetectionModule):
    def __init__(self, config: dict):
        super().__init__(config, 'custom_detector')
        
    def analyze_packet(self, packet_info, ip_stats):
        # Your detection logic here
        if suspicious_condition:
            return DetectionResult(
                threat_type="CUSTOM_THREAT",
                score=75,
                confidence=0.9,
                details="Custom detection triggered",
                source_ip=packet_info.src_ip
            )
        return None
```

### Machine Learning Integration

The agent supports ML-based detection through the anomaly detection module:

```python
# Enable ML features in configuration
features:
  machine_learning: true
  
anomaly:
  enabled: true
  model_type: "isolation_forest"
  training_samples: 10000
  retrain_interval: 3600
```

### Threat Intelligence Integration

Configure external threat feeds:

```yaml
threat_intel:
  enabled: true
  feeds:
    - url: "https://threatfeed.example.com/ips.txt"
      format: "text"
      update_interval: 1800
      weight: 0.8
    - url: "https://api.threatdb.com/malicious"
      format: "json"
      api_key: "your-api-key"
      update_interval: 900
      weight: 0.9
```

## 🐛 Troubleshooting

### Common Issues

**Permission Denied Errors:**
```bash
# Ensure proper capabilities are set
sudo setcap cap_net_raw,cap_net_admin+eip /opt/security-agent/venv/bin/python3

# Check user permissions
sudo usermod -a -G security-agent $USER
```

**High CPU Usage:**
```bash
# Check packet processing rate
security-agent stats | grep packets_per_second

# Reduce packet capture rate
echo "network.snaplen: 128" >> /opt/security-agent/config/security_agent.yaml
```

**False Positive Blocks:**
```bash
# Add legitimate IPs to allowlist
security-agent unblock 192.168.1.10
echo "  - 192.168.1.10/32" >> /opt/security-agent/config/security_agent.yaml
```

### Log Analysis

```bash
# View detection logs
journalctl -u security-agent | grep DETECTION

# View blocking actions
journalctl -u security-agent | grep BLOCKED

# Check for errors
journalctl -u security-agent -p err

# Real-time monitoring
tail -f /var/log/security-agent/agent.log | jq
```

### Performance Tuning

```yaml
# Optimize for high-traffic networks
performance:
  max_tracked_ips: 50000
  state_cleanup_interval: 60
  packet_buffer_size: 65536
  
network:
  snaplen: 128  # Capture only headers
  timeout_ms: 10  # Reduce timeout for faster processing
  
detection:
  batch_size: 1000  # Process packets in batches
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Support

- **Documentation**: [https://docs.security-agent.com](https://docs.security-agent.com)
- **Issues**: [GitHub Issues](https://github.com/your-org/network-security-agent/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/network-security-agent/discussions)
- **Security Issues**: security@security-agent.com

## 🙏 Acknowledgments

- [Scapy](https://scapy.net/) for packet manipulation capabilities
- [nftables](https://netfilter.org/projects/nftables/) for modern firewall management
- [Prometheus](https://prometheus.io/) for metrics and monitoring
- [MITRE ATT&CK](https://attack.mitre.org/) for threat categorization framework

---

**⚡ Built with security and performance in mind**

*Network Security Agent - Protecting your infrastructure, one packet at a time.*
