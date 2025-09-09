#!/usr/bin/env python3
"""
Network Security Agent - Decision Engine and Firewall Interface
Implements decision making logic and firewall management.
"""

import time
import subprocess
import threading
from collections import defaultdict
from typing import Dict, List, Optional, Set
import logging
import ipaddress
import json

logger = logging.getLogger(__name__)

class BlockAction:
    """Represents a blocking action"""
    def __init__(self, ip: str, reason: str, score: int, ttl: int, timestamp: float = None):
        self.ip = ip
        self.reason = reason
        self.score = score
        self.ttl = ttl  # Time to live in seconds
        self.timestamp = timestamp or time.time()
        self.expires_at = self.timestamp + ttl
        
    def is_expired(self, current_time: float = None) -> bool:
        """Check if the block has expired"""
        current_time = current_time or time.time()
        return current_time >= self.expires_at
    
    def time_remaining(self, current_time: float = None) -> int:
        """Get remaining block time in seconds"""
        current_time = current_time or time.time()
        remaining = int(self.expires_at - current_time)
        return max(0, remaining)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'ip': self.ip,
            'reason': self.reason,
            'score': self.score,
            'ttl': self.ttl,
            'timestamp': self.timestamp,
            'expires_at': self.expires_at,
            'time_remaining': self.time_remaining()
        }

class FirewallInterface:
    """Interface for managing firewall rules"""
    
    def __init__(self, config: dict):
        self.config = config
        self.backend = config['blocking']['firewall']['backend']
        self.chain = config['blocking']['firewall']['chain']
        self.table = config['blocking']['firewall']['table']
        
        # Initialize firewall
        self._initialize_firewall()
        
    def _initialize_firewall(self):
        """Initialize firewall chains and tables"""
        try:
            if self.backend == "nftables":
                self._init_nftables()
            elif self.backend == "iptables":
                self._init_iptables()
            elif self.backend == "mock":
                logger.info("Using mock firewall backend for testing")
            else:
                raise ValueError(f"Unsupported firewall backend: {self.backend}")
                
        except Exception as e:
            logger.error(f"Failed to initialize firewall: {e}")
            # Fall back to mock mode
            self.backend = "mock"
            logger.warning("Falling back to mock firewall mode")
    
    def _init_nftables(self):
        """Initialize nftables rules"""
        commands = [
            # Create table if it doesn't exist
            f"nft add table inet {self.table}",
            
            # Create chain if it doesn't exist
            f"nft add chain inet {self.table} {self.chain} {{ type filter hook input priority 0\\; }}",
            
            # Create set for blocked IPs
            f"nft add set inet {self.table} blocked_ips {{ type ipv4_addr\\; flags timeout\\; }}",
        ]
        
        for cmd in commands:
            try:
                subprocess.run(cmd.split(), check=False, capture_output=True, text=True)
            except Exception as e:
                logger.debug(f"nftables command failed (may be expected): {cmd} - {e}")
        
        # Add rule to drop packets from blocked IPs
        drop_rule = f"nft add rule inet {self.table} {self.chain} ip saddr @blocked_ips drop"
        try:
            subprocess.run(drop_rule.split(), check=False, capture_output=True, text=True)
        except Exception as e:
            logger.debug(f"nftables drop rule command: {e}")
        
        logger.info("nftables firewall initialized")
    
    def _init_iptables(self):
        """Initialize iptables rules"""
        commands = [
            # Create chain if it doesn't exist
            f"iptables -N {self.chain}",
            
            # Insert reference to our chain in INPUT
            f"iptables -I INPUT -j {self.chain}",
            
            # Create ipset for blocked IPs
            f"ipset create blocked_ips hash:ip timeout 0",
        ]
        
        for cmd in commands:
            try:
                subprocess.run(cmd.split(), check=False, capture_output=True, text=True)
            except Exception as e:
                logger.debug(f"iptables command failed (may be expected): {cmd} - {e}")
        
        # Add rule to drop packets from blocked IPs
        drop_rule = f"iptables -A {self.chain} -m set --match-set blocked_ips src -j DROP"
        try:
            subprocess.run(drop_rule.split(), check=False, capture_output=True, text=True)
        except Exception as e:
            logger.debug(f"iptables drop rule command: {e}")
        
        logger.info("iptables firewall initialized")
    
    def block_ip(self, ip: str, ttl: int) -> bool:
        """Block an IP address with specified TTL"""
        try:
            if self.backend == "nftables":
                return self._nft_block_ip(ip, ttl)
            elif self.backend == "iptables":
                return self._ipt_block_ip(ip, ttl)
            elif self.backend == "mock":
                logger.info(f"MOCK: Would block {ip} for {ttl} seconds")
                return True
            return False
            
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address"""
        try:
            if self.backend == "nftables":
                return self._nft_unblock_ip(ip)
            elif self.backend == "iptables":
                return self._ipt_unblock_ip(ip)
            elif self.backend == "mock":
                logger.info(f"MOCK: Would unblock {ip}")
                return True
            return False
            
        except Exception as e:
            logger.error(f"Failed to unblock IP {ip}: {e}")
            return False
    
    def _nft_block_ip(self, ip: str, ttl: int) -> bool:
        """Block IP using nftables"""
        cmd = f"nft add element inet {self.table} blocked_ips {{ {ip} timeout {ttl}s }}"
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info(f"nftables: Blocked {ip} for {ttl} seconds")
            return True
        else:
            logger.error(f"nftables block failed: {result.stderr}")
            return False
    
    def _nft_unblock_ip(self, ip: str) -> bool:
        """Unblock IP using nftables"""
        cmd = f"nft delete element inet {self.table} blocked_ips {{ {ip} }}"
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info(f"nftables: Unblocked {ip}")
            return True
        else:
            logger.debug(f"nftables unblock (may not exist): {result.stderr}")
            return True  # Consider it success if IP wasn't in set
    
    def _ipt_block_ip(self, ip: str, ttl: int) -> bool:
        """Block IP using iptables/ipset"""
        cmd = f"ipset add blocked_ips {ip} timeout {ttl}"
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info(f"iptables: Blocked {ip} for {ttl} seconds")
            return True
        else:
            logger.error(f"iptables block failed: {result.stderr}")
            return False
    
    def _ipt_unblock_ip(self, ip: str) -> bool:
        """Unblock IP using iptables/ipset"""
        cmd = f"ipset del blocked_ips {ip}"
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info(f"iptables: Unblocked {ip}")
            return True
        else:
            logger.debug(f"iptables unblock (may not exist): {result.stderr}")
            return True  # Consider it success if IP wasn't in set
    
    def list_blocked_ips(self) -> List[str]:
        """List currently blocked IPs"""
        try:
            if self.backend == "nftables":
                return self._nft_list_blocked()
            elif self.backend == "iptables":
                return self._ipt_list_blocked()
            elif self.backend == "mock":
                return []  # Mock mode doesn't track real blocks
            return []
            
        except Exception as e:
            logger.error(f"Failed to list blocked IPs: {e}")
            return []
    
    def _nft_list_blocked(self) -> List[str]:
        """List blocked IPs from nftables"""
        cmd = f"nft list set inet {self.table} blocked_ips"
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        
        ips = []
        if result.returncode == 0:
            # Parse nftables output to extract IPs
            for line in result.stdout.split('\n'):
                if 'elements' in line:
                    # Extract IPs from elements line
                    import re
                    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                    ips.extend(re.findall(ip_pattern, line))
        
        return ips
    
    def _ipt_list_blocked(self) -> List[str]:
        """List blocked IPs from ipset"""
        cmd = "ipset list blocked_ips"
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        
        ips = []
        if result.returncode == 0:
            # Parse ipset output to extract IPs
            in_members = False
            for line in result.stdout.split('\n'):
                if line.startswith('Members:'):
                    in_members = True
                    continue
                if in_members and line.strip():
                    ip = line.strip().split()[0]  # First part is IP
                    if self._is_valid_ip(ip):
                        ips.append(ip)
        
        return ips
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def cleanup(self):
        """Cleanup firewall rules on shutdown"""
        try:
            if self.backend == "nftables":
                # Flush our set
                subprocess.run(f"nft flush set inet {self.table} blocked_ips".split(), 
                             check=False, capture_output=True)
            elif self.backend == "iptables":
                # Flush ipset
                subprocess.run("ipset flush blocked_ips".split(), 
                             check=False, capture_output=True)
            logger.info("Firewall cleanup completed")
        except Exception as e:
            logger.error(f"Firewall cleanup failed: {e}")

class DecisionEngine:
    """Main decision engine for threat response"""
    
    def __init__(self, config: dict):
        self.config = config
        self.firewall = FirewallInterface(config)
        
        # Threat scoring weights
        self.weights = config['scoring']['weights']
        self.thresholds = config['scoring']['thresholds']
        
        # Block TTL settings
        self.ttl_settings = config['blocking']['ttl']
        
        # Access control lists
        self.allowlist = self._parse_cidr_list(config['access_control']['allowlist'])
        self.denylist = self._parse_cidr_list(config['access_control']['denylist'])
        
        # Active blocks tracking
        self.active_blocks: Dict[str, BlockAction] = {}
        self.blocks_lock = threading.Lock()
        
        # Statistics
        self.stats = {
            'blocks_applied': 0,
            'blocks_expired': 0,
            'detections_processed': 0,
            'false_positives': 0
        }
        
        # Start cleanup thread
        self._start_cleanup_thread()
        
        logger.info("Decision engine initialized")
    
    def _parse_cidr_list(self, cidr_list: List[str]) -> List[ipaddress.IPv4Network]:
        """Parse CIDR notation list into network objects"""
        networks = []
        for cidr in cidr_list:
            try:
                networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError as e:
                logger.warning(f"Invalid CIDR notation '{cidr}': {e}")
        return networks
    
    def _is_in_allowlist(self, ip: str) -> bool:
        """Check if IP is in allowlist"""
        try:
            ip_addr = ipaddress.ip_address(ip)
            return any(ip_addr in network for network in self.allowlist)
        except ValueError:
            return False
    
    def _is_in_denylist(self, ip: str) -> bool:
        """Check if IP is in denylist"""
        try:
            ip_addr = ipaddress.ip_address(ip)
            return any(ip_addr in network for network in self.denylist)
        except ValueError:
            return False
    
    def process_detection(self, detection_result) -> Optional[BlockAction]:
        """Process a detection result and make blocking decision"""
        self.stats['detections_processed'] += 1
        
        ip = detection_result.source_ip
        threat_type = detection_result.threat_type
        base_score = detection_result.score
        
        # Check allowlist first
        if self._is_in_allowlist(ip):
            logger.debug(f"IP {ip} is in allowlist, skipping block")
            return None
        
        # Auto-block if in denylist
        if self._is_in_denylist(ip):
            logger.info(f"IP {ip} is in denylist, applying immediate block")
            return self._apply_block(ip, "DENYLIST", 100, self.ttl_settings['critical'])
        
        # Calculate weighted score
        weight = self.weights.get(threat_type.lower(), 1)
        final_score = min(100, base_score * weight / 100)
        
        # Determine action based on score
        if final_score >= self.thresholds['ban_threshold']:
            # Apply block
            ttl = self._get_ttl_for_threat(threat_type)
            reason = f"{threat_type} (score: {final_score:.1f})"
            return self._apply_block(ip, reason, final_score, ttl)
            
        elif final_score >= self.thresholds['warn_threshold']:
            # Apply rate limiting (if enabled)
            if self.config['blocking']['rate_limit']['enabled']:
                logger.warning(f"Rate limiting {ip}: {threat_type} (score: {final_score:.1f})")
                # In a full implementation, this would apply rate limiting
                # For now, we just log the warning
            
        else:
            logger.debug(f"Low threat score for {ip}: {final_score:.1f}")
        
        return None
    
    def _get_ttl_for_threat(self, threat_type: str) -> int:
        """Get appropriate TTL for threat type"""
        threat_mapping = {
            'PORT_SCAN': 'port_scan',
            'SYN_FLOOD': 'dos_attack',
            'UDP_FLOOD': 'dos_attack',
            'ICMP_FLOOD': 'dos_attack',
            'HTTP_FLOOD': 'dos_attack',
            'DNS_AMPLIFICATION': 'dos_attack',
            'THREAT_INTEL': 'critical',
            'ANOMALY': 'default'
        }
        
        ttl_key = threat_mapping.get(threat_type, 'default')
        return self.ttl_settings[ttl_key]
    
    def _apply_block(self, ip: str, reason: str, score: float, ttl: int) -> BlockAction:
        """Apply firewall block for IP"""
        with self.blocks_lock:
            # Check if already blocked
            if ip in self.active_blocks:
                existing_block = self.active_blocks[ip]
                if not existing_block.is_expired():
                    logger.debug(f"IP {ip} already blocked")
                    return existing_block
            
            # Create new block
            block = BlockAction(ip, reason, score, ttl)
            
            # Apply firewall rule
            if self.firewall.block_ip(ip, ttl):
                self.active_blocks[ip] = block
                self.stats['blocks_applied'] += 1
                
                logger.warning(f"BLOCKED {ip}: {reason} (TTL: {ttl}s)")
                
                # Log block event
                self._log_block_event(block)
                
                return block
            else:
                logger.error(f"Failed to apply firewall block for {ip}")
                return None
    
    def _log_block_event(self, block: BlockAction):
        """Log block event in structured format"""
        if self.config['logging']['events']['log_blocks']:
            event = {
                'event_type': 'ip_blocked',
                'timestamp': time.time(),
                'ip': block.ip,
                'reason': block.reason,
                'score': block.score,
                'ttl': block.ttl,
                'expires_at': block.expires_at
            }
            
            # In production, this would go to a structured logging system
            logger.info(f"BLOCK_EVENT: {json.dumps(event)}")
    
    def unblock_ip(self, ip: str, reason: str = "manual") -> bool:
        """Manually unblock an IP"""
        with self.blocks_lock:
            if ip in self.active_blocks:
                if self.firewall.unblock_ip(ip):
                    block = self.active_blocks.pop(ip)
                    logger.info(f"UNBLOCKED {ip}: {reason}")
                    
                    # Log unblock event
                    if self.config['logging']['events']['log_unblocks']:
                        event = {
                            'event_type': 'ip_unblocked',
                            'timestamp': time.time(),
                            'ip': ip,
                            'reason': reason,
                            'original_block_reason': block.reason,
                            'time_remaining': block.time_remaining()
                        }
                        logger.info(f"UNBLOCK_EVENT: {json.dumps(event)}")
                    
                    return True
                else:
                    logger.error(f"Failed to remove firewall block for {ip}")
                    return False
            else:
                logger.warning(f"IP {ip} not currently blocked")
                return False
    
    def get_blocked_ips(self) -> Dict[str, BlockAction]:
        """Get all currently blocked IPs"""
        with self.blocks_lock:
            return self.active_blocks.copy()
    
    def get_block_info(self, ip: str) -> Optional[BlockAction]:
        """Get block information for specific IP"""
        with self.blocks_lock:
            return self.active_blocks.get(ip)
    
    def cleanup_expired_blocks(self):
        """Remove expired blocks"""
        current_time = time.time()
        expired_ips = []
        
        with self.blocks_lock:
            for ip, block in list(self.active_blocks.items()):
                if block.is_expired(current_time):
                    expired_ips.append(ip)
                    del self.active_blocks[ip]
                    self.stats['blocks_expired'] += 1
        
        # Remove from firewall (redundant with TTL, but good for cleanup)
        for ip in expired_ips:
            self.firewall.unblock_ip(ip)
            logger.debug(f"Cleaned up expired block for {ip}")
    
    def _start_cleanup_thread(self):
        """Start background thread for cleanup tasks"""
        def cleanup_worker():
            while True:
                try:
                    time.sleep(60)  # Run every minute
                    self.cleanup_expired_blocks()
                except Exception as e:
                    logger.error(f"Error in cleanup thread: {e}")
        
        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        cleanup_thread.start()
        logger.info("Started cleanup thread")
    
    def get_stats(self) -> dict:
        """Get decision engine statistics"""
        with self.blocks_lock:
            stats = self.stats.copy()
            stats['active_blocks'] = len(self.active_blocks)
            stats['allowlist_size'] = len(self.allowlist)
            stats['denylist_size'] = len(self.denylist)
        return stats
    
    def shutdown(self):
        """Cleanup on shutdown"""
        logger.info("Shutting down decision engine")
        
        # Optionally remove all blocks on shutdown
        if self.config.get('development', {}).get('remove_blocks_on_exit', False):
            with self.blocks_lock:
                for ip in list(self.active_blocks.keys()):
                    self.firewall.unblock_ip(ip)
                self.active_blocks.clear()
        
        # Cleanup firewall
        self.firewall.cleanup()

if __name__ == "__main__":
    # Test decision engine
    import yaml
    from detection_modules import DetectionResult
    
    config_path = "/workspaces/codespaces-blank/network-security-agent/config/security_agent.yaml"
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    engine = DecisionEngine(config)
    
    # Test detection
    test_result = DetectionResult(
        threat_type="SYN_FLOOD",
        score=85,
        confidence=0.9,
        details="Test detection",
        source_ip="192.168.1.100"
    )
    
    block = engine.process_detection(test_result)
    if block:
        print(f"Applied block: {block.to_dict()}")
    
    print(f"Stats: {engine.get_stats()}")
    
    # Cleanup
    engine.shutdown()
