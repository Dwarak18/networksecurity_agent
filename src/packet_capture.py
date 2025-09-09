#!/usr/bin/env python3
"""
Network Security Agent - Packet Capture Engine
Real-time network traffic capture and analysis for threat detection.
"""

import time
import struct
import socket
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import logging
import yaml
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.dns import DNS

logger = logging.getLogger(__name__)

@dataclass
class PacketInfo:
    """Structured packet information for analysis"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = ""
    packet_size: int = 0
    tcp_flags: Optional[int] = None
    payload_size: int = 0
    is_syn: bool = False
    is_ack: bool = False
    is_fin: bool = False
    is_rst: bool = False
    http_method: Optional[str] = None
    dns_query: Optional[str] = None
    dns_response_size: int = 0

@dataclass
class IPStats:
    """Per-IP statistics and counters"""
    # Packet counts
    total_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    
    # TCP-specific counters
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    
    # Protocol-specific counters
    http_requests: int = 0
    dns_queries: int = 0
    dns_responses: int = 0
    
    # Port scanning indicators
    unique_dst_ports: set = field(default_factory=set)
    port_connections: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    
    # Traffic volume
    bytes_sent: int = 0
    bytes_received: int = 0
    
    # Timing information
    first_seen: float = 0.0
    last_seen: float = 0.0
    
    # Sliding window data
    packet_timestamps: deque = field(default_factory=deque)
    syn_timestamps: deque = field(default_factory=deque)
    udp_timestamps: deque = field(default_factory=deque)
    icmp_timestamps: deque = field(default_factory=deque)
    http_timestamps: deque = field(default_factory=deque)
    
    def update_sliding_windows(self, current_time: float, window_size: int):
        """Remove old entries from sliding windows"""
        cutoff_time = current_time - window_size
        
        # Clean up timestamp deques
        for timestamps in [self.packet_timestamps, self.syn_timestamps, 
                          self.udp_timestamps, self.icmp_timestamps, self.http_timestamps]:
            while timestamps and timestamps[0] < cutoff_time:
                timestamps.popleft()

class PacketCaptureEngine:
    """Main packet capture and analysis engine"""
    
    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.setup_logging()
        
        # State tracking
        self.ip_stats: Dict[str, IPStats] = {}
        self.stats_lock = threading.Lock()
        
        # Capture control
        self.running = False
        self.capture_thread: Optional[threading.Thread] = None
        
        # Detection modules will be initialized later
        self.detection_modules = []
        
        # Initialize network interface
        self.interface = self._detect_interface()
        
        logger.info(f"Packet capture engine initialized on interface {self.interface}")
    
    def _load_config(self, config_path: str) -> dict:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            raise
    
    def setup_logging(self):
        """Configure logging based on config"""
        log_level = getattr(logging, self.config['performance']['log_level'])
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    def _detect_interface(self) -> str:
        """Auto-detect network interface or use configured one"""
        configured_iface = self.config['network']['interface']
        if configured_iface and configured_iface != "auto":
            return configured_iface
        
        # Auto-detect active interface
        try:
            # Get default route interface
            import netifaces
            gateways = netifaces.gateways()
            default_interface = gateways['default'][netifaces.AF_INET][1]
            logger.info(f"Auto-detected interface: {default_interface}")
            return default_interface
        except:
            # Fallback to common interface names
            common_interfaces = ['eth0', 'ens33', 'enp0s3', 'wlan0']
            for iface in common_interfaces:
                try:
                    socket.socket(socket.AF_INET, socket.SOCK_DGRAM).bind((iface, 0))
                    logger.info(f"Using fallback interface: {iface}")
                    return iface
                except:
                    continue
            
            logger.warning("Could not detect interface, using 'any'")
            return "any"
    
    def parse_packet(self, packet) -> Optional[PacketInfo]:
        """Parse packet and extract relevant information"""
        try:
            if not packet.haslayer(IP):
                return None
            
            ip_layer = packet[IP]
            info = PacketInfo(
                timestamp=time.time(),
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                protocol=ip_layer.proto,
                packet_size=len(packet)
            )
            
            # Parse TCP layer
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                info.src_port = tcp_layer.sport
                info.dst_port = tcp_layer.dport
                info.protocol = "TCP"
                info.tcp_flags = tcp_layer.flags
                info.payload_size = len(tcp_layer.payload)
                
                # TCP flags
                info.is_syn = bool(tcp_layer.flags & 0x02)
                info.is_ack = bool(tcp_layer.flags & 0x10)
                info.is_fin = bool(tcp_layer.flags & 0x01)
                info.is_rst = bool(tcp_layer.flags & 0x04)
                
                # HTTP detection
                if packet.haslayer(HTTPRequest):
                    http_layer = packet[HTTPRequest]
                    info.http_method = http_layer.Method.decode() if http_layer.Method else None
            
            # Parse UDP layer
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                info.src_port = udp_layer.sport
                info.dst_port = udp_layer.dport
                info.protocol = "UDP"
                info.payload_size = len(udp_layer.payload)
                
                # DNS detection
                if packet.haslayer(DNS):
                    dns_layer = packet[DNS]
                    if dns_layer.qr == 0:  # Query
                        info.dns_query = dns_layer.qd.qname.decode() if dns_layer.qd else None
                    else:  # Response
                        info.dns_response_size = len(packet[UDP].payload)
            
            # Parse ICMP layer
            elif packet.haslayer(ICMP):
                info.protocol = "ICMP"
                info.payload_size = len(packet[ICMP].payload)
            
            return info
            
        except Exception as e:
            logger.debug(f"Error parsing packet: {e}")
            return None
    
    def update_ip_stats(self, packet_info: PacketInfo):
        """Update per-IP statistics"""
        current_time = packet_info.timestamp
        src_ip = packet_info.src_ip
        
        with self.stats_lock:
            # Initialize stats if new IP
            if src_ip not in self.ip_stats:
                self.ip_stats[src_ip] = IPStats()
                self.ip_stats[src_ip].first_seen = current_time
            
            stats = self.ip_stats[src_ip]
            stats.last_seen = current_time
            
            # Update packet counts
            stats.total_packets += 1
            stats.packet_timestamps.append(current_time)
            
            if packet_info.protocol == "TCP":
                stats.tcp_packets += 1
                
                # TCP flags
                if packet_info.is_syn:
                    stats.syn_count += 1
                    stats.syn_timestamps.append(current_time)
                if packet_info.is_ack:
                    stats.ack_count += 1
                if packet_info.is_fin:
                    stats.fin_count += 1
                if packet_info.is_rst:
                    stats.rst_count += 1
                
                # Port tracking for scan detection
                if packet_info.dst_port:
                    stats.unique_dst_ports.add(packet_info.dst_port)
                    stats.port_connections[packet_info.dst_port] += 1
                
                # HTTP requests
                if packet_info.http_method:
                    stats.http_requests += 1
                    stats.http_timestamps.append(current_time)
            
            elif packet_info.protocol == "UDP":
                stats.udp_packets += 1
                stats.udp_timestamps.append(current_time)
                
                # DNS tracking
                if packet_info.dns_query:
                    stats.dns_queries += 1
                elif packet_info.dns_response_size > 0:
                    stats.dns_responses += 1
            
            elif packet_info.protocol == "ICMP":
                stats.icmp_packets += 1
                stats.icmp_timestamps.append(current_time)
            
            # Update traffic volume
            stats.bytes_sent += packet_info.packet_size
            
            # Clean up old entries
            window_size = self.config['time_windows']['medium_window']
            stats.update_sliding_windows(current_time, window_size)
    
    def packet_handler(self, packet):
        """Handle captured packets"""
        try:
            packet_info = self.parse_packet(packet)
            if packet_info:
                self.update_ip_stats(packet_info)
                
                # Trigger detection modules
                for detection_module in self.detection_modules:
                    detection_module.analyze_packet(packet_info, self.ip_stats[packet_info.src_ip])
                    
        except Exception as e:
            logger.error(f"Error in packet handler: {e}")
    
    def start_capture(self):
        """Start packet capture"""
        if self.running:
            logger.warning("Capture already running")
            return
        
        self.running = True
        logger.info(f"Starting packet capture on {self.interface}")
        
        try:
            # Configure capture parameters
            capture_filter = self._build_capture_filter()
            
            # Start capture
            if self.config['development']['pcap_file']:
                # Read from pcap file for testing
                logger.info(f"Reading from pcap file: {self.config['development']['pcap_file']}")
                sniff(offline=self.config['development']['pcap_file'], 
                      prn=self.packet_handler, 
                      stop_filter=lambda x: not self.running)
            else:
                # Live capture
                sniff(iface=self.interface,
                      prn=self.packet_handler,
                      filter=capture_filter,
                      store=0,  # Don't store packets in memory
                      stop_filter=lambda x: not self.running)
                      
        except Exception as e:
            logger.error(f"Capture error: {e}")
            self.running = False
    
    def _build_capture_filter(self) -> str:
        """Build BPF filter for packet capture"""
        # Basic filter to capture TCP, UDP, and ICMP
        return "ip and (tcp or udp or icmp)"
    
    def stop_capture(self):
        """Stop packet capture"""
        logger.info("Stopping packet capture")
        self.running = False
    
    def get_ip_stats(self, ip: str) -> Optional[IPStats]:
        """Get statistics for a specific IP"""
        with self.stats_lock:
            return self.ip_stats.get(ip)
    
    def get_all_stats(self) -> Dict[str, IPStats]:
        """Get all IP statistics"""
        with self.stats_lock:
            return self.ip_stats.copy()
    
    def cleanup_old_stats(self):
        """Remove old IP statistics to free memory"""
        current_time = time.time()
        cleanup_threshold = self.config['time_windows']['long_window']
        max_ips = self.config['performance']['max_tracked_ips']
        
        with self.stats_lock:
            # Remove old entries
            old_ips = [ip for ip, stats in self.ip_stats.items() 
                      if current_time - stats.last_seen > cleanup_threshold]
            
            for ip in old_ips:
                del self.ip_stats[ip]
            
            # Limit memory usage by keeping only recent IPs
            if len(self.ip_stats) > max_ips:
                # Sort by last seen and keep most recent
                sorted_ips = sorted(self.ip_stats.items(), 
                                  key=lambda x: x[1].last_seen, reverse=True)
                
                # Keep only the most recent IPs
                self.ip_stats = dict(sorted_ips[:max_ips])
            
            if old_ips:
                logger.debug(f"Cleaned up {len(old_ips)} old IP entries")
    
    def start_cleanup_thread(self):
        """Start background cleanup thread"""
        def cleanup_worker():
            while self.running:
                time.sleep(self.config['performance']['state_cleanup_interval'])
                self.cleanup_old_stats()
        
        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        cleanup_thread.start()
        logger.info("Started cleanup thread")

if __name__ == "__main__":
    # Test the packet capture engine
    engine = PacketCaptureEngine("/workspaces/codespaces-blank/network-security-agent/config/security_agent.yaml")
    
    try:
        engine.start_cleanup_thread()
        engine.start_capture()
    except KeyboardInterrupt:
        logger.info("Shutting down packet capture")
        engine.stop_capture()
