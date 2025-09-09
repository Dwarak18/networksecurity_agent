#!/usr/bin/env python3
"""
Network Security Agent - Detection Modules
Implements various detection algorithms for network attacks.
"""

import time
import statistics
from abc import ABC, abstractmethod
from collections import deque
from typing import Dict, List, Optional, Tuple
import logging
import math

logger = logging.getLogger(__name__)

class DetectionResult:
    """Result of a detection analysis"""
    def __init__(self, threat_type: str, score: int, confidence: float, 
                 details: str, source_ip: str, timestamp: float = None):
        self.threat_type = threat_type
        self.score = score
        self.confidence = confidence
        self.details = details
        self.source_ip = source_ip
        self.timestamp = timestamp or time.time()
        
    def __str__(self):
        return f"DetectionResult(type={self.threat_type}, score={self.score}, " \
               f"confidence={self.confidence:.2f}, ip={self.source_ip})"

class BaseDetectionModule(ABC):
    """Base class for all detection modules"""
    
    def __init__(self, config: dict, name: str):
        self.config = config
        self.name = name
        self.enabled = config.get('detection', {}).get(name, {}).get('enabled', True)
        
    @abstractmethod
    def analyze_packet(self, packet_info, ip_stats) -> Optional[DetectionResult]:
        """Analyze a packet and return detection result if threat found"""
        pass
    
    def is_enabled(self) -> bool:
        """Check if this detection module is enabled"""
        return self.enabled

class SynFloodDetector(BaseDetectionModule):
    """Detects SYN flood attacks"""
    
    def __init__(self, config: dict):
        super().__init__(config, 'syn_flood')
        self.syn_rate_threshold = config['detection']['syn_flood']['syn_rate_threshold']
        self.syn_ack_ratio_threshold = config['detection']['syn_flood']['syn_ack_ratio_threshold']
        self.window_size = config['detection']['syn_flood']['window_size']
        
    def analyze_packet(self, packet_info, ip_stats) -> Optional[DetectionResult]:
        if not self.is_enabled() or packet_info.protocol != "TCP":
            return None
        
        current_time = packet_info.timestamp
        
        # Calculate SYN rate in the window
        syn_count = len([t for t in ip_stats.syn_timestamps 
                        if current_time - t <= self.window_size])
        syn_rate = syn_count / self.window_size
        
        # Calculate SYN/ACK ratio
        ack_count = ip_stats.ack_count
        syn_ack_ratio = ack_count / max(ip_stats.syn_count, 1)
        
        # Check thresholds
        if (syn_rate > self.syn_rate_threshold and 
            syn_ack_ratio < self.syn_ack_ratio_threshold):
            
            score = min(100, int((syn_rate / self.syn_rate_threshold) * 30))
            confidence = 0.8 + min(0.2, (syn_rate - self.syn_rate_threshold) / self.syn_rate_threshold)
            
            details = f"SYN rate: {syn_rate:.1f}/s (threshold: {self.syn_rate_threshold}), " \
                     f"SYN/ACK ratio: {syn_ack_ratio:.2f} (threshold: {self.syn_ack_ratio_threshold})"
            
            return DetectionResult(
                threat_type="SYN_FLOOD",
                score=score,
                confidence=confidence,
                details=details,
                source_ip=packet_info.src_ip,
                timestamp=current_time
            )
        
        return None

class UdpFloodDetector(BaseDetectionModule):
    """Detects UDP flood attacks"""
    
    def __init__(self, config: dict):
        super().__init__(config, 'udp_flood')
        self.udp_pps_threshold = config['detection']['udp_flood']['udp_pps_threshold']
        self.window_size = config['detection']['udp_flood']['window_size']
        
    def analyze_packet(self, packet_info, ip_stats) -> Optional[DetectionResult]:
        if not self.is_enabled() or packet_info.protocol != "UDP":
            return None
        
        current_time = packet_info.timestamp
        
        # Calculate UDP packet rate
        udp_count = len([t for t in ip_stats.udp_timestamps 
                        if current_time - t <= self.window_size])
        udp_rate = udp_count / self.window_size
        
        if udp_rate > self.udp_pps_threshold:
            score = min(100, int((udp_rate / self.udp_pps_threshold) * 25))
            confidence = 0.7 + min(0.3, (udp_rate - self.udp_pps_threshold) / self.udp_pps_threshold)
            
            details = f"UDP rate: {udp_rate:.1f} pps (threshold: {self.udp_pps_threshold})"
            
            return DetectionResult(
                threat_type="UDP_FLOOD",
                score=score,
                confidence=confidence,
                details=details,
                source_ip=packet_info.src_ip,
                timestamp=current_time
            )
        
        return None

class IcmpFloodDetector(BaseDetectionModule):
    """Detects ICMP flood attacks"""
    
    def __init__(self, config: dict):
        super().__init__(config, 'icmp_flood')
        self.icmp_pps_threshold = config['detection']['icmp_flood']['icmp_pps_threshold']
        self.window_size = config['detection']['icmp_flood']['window_size']
        
    def analyze_packet(self, packet_info, ip_stats) -> Optional[DetectionResult]:
        if not self.is_enabled() or packet_info.protocol != "ICMP":
            return None
        
        current_time = packet_info.timestamp
        
        # Calculate ICMP packet rate
        icmp_count = len([t for t in ip_stats.icmp_timestamps 
                         if current_time - t <= self.window_size])
        icmp_rate = icmp_count / self.window_size
        
        if icmp_rate > self.icmp_pps_threshold:
            score = min(100, int((icmp_rate / self.icmp_pps_threshold) * 20))
            confidence = 0.6 + min(0.4, (icmp_rate - self.icmp_pps_threshold) / self.icmp_pps_threshold)
            
            details = f"ICMP rate: {icmp_rate:.1f} pps (threshold: {self.icmp_pps_threshold})"
            
            return DetectionResult(
                threat_type="ICMP_FLOOD",
                score=score,
                confidence=confidence,
                details=details,
                source_ip=packet_info.src_ip,
                timestamp=current_time
            )
        
        return None

class PortScanDetector(BaseDetectionModule):
    """Detects port scanning attacks"""
    
    def __init__(self, config: dict):
        super().__init__(config, 'port_scan')
        self.unique_ports_threshold = config['detection']['port_scan']['unique_ports_threshold']
        self.window_size = config['detection']['port_scan']['window_size']
        self.connection_threshold = config['detection']['port_scan']['connection_threshold']
        
    def analyze_packet(self, packet_info, ip_stats) -> Optional[DetectionResult]:
        if not self.is_enabled() or packet_info.protocol != "TCP":
            return None
        
        current_time = packet_info.timestamp
        
        # Count unique destination ports
        unique_ports = len(ip_stats.unique_dst_ports)
        
        # Count ports with low connection attempts (scan indicators)
        low_connection_ports = sum(1 for count in ip_stats.port_connections.values() 
                                  if count <= self.connection_threshold)
        
        if unique_ports > self.unique_ports_threshold:
            # Calculate scan intensity
            scan_ratio = low_connection_ports / max(unique_ports, 1)
            
            score = min(100, int((unique_ports / self.unique_ports_threshold) * 35))
            confidence = 0.7 + min(0.3, scan_ratio)
            
            details = f"Unique ports: {unique_ports} (threshold: {self.unique_ports_threshold}), " \
                     f"scan ratio: {scan_ratio:.2f}"
            
            return DetectionResult(
                threat_type="PORT_SCAN",
                score=score,
                confidence=confidence,
                details=details,
                source_ip=packet_info.src_ip,
                timestamp=current_time
            )
        
        return None

class HttpFloodDetector(BaseDetectionModule):
    """Detects HTTP request flood attacks"""
    
    def __init__(self, config: dict):
        super().__init__(config, 'http_flood')
        self.http_req_threshold = config['detection']['http_flood']['http_req_threshold']
        self.window_size = config['detection']['http_flood']['window_size']
        
    def analyze_packet(self, packet_info, ip_stats) -> Optional[DetectionResult]:
        if not self.is_enabled() or not packet_info.http_method:
            return None
        
        current_time = packet_info.timestamp
        
        # Calculate HTTP request rate
        http_count = len([t for t in ip_stats.http_timestamps 
                         if current_time - t <= self.window_size])
        http_rate = http_count / self.window_size
        
        if http_rate > self.http_req_threshold:
            score = min(100, int((http_rate / self.http_req_threshold) * 25))
            confidence = 0.8 + min(0.2, (http_rate - self.http_req_threshold) / self.http_req_threshold)
            
            details = f"HTTP rate: {http_rate:.1f} req/s (threshold: {self.http_req_threshold})"
            
            return DetectionResult(
                threat_type="HTTP_FLOOD",
                score=score,
                confidence=confidence,
                details=details,
                source_ip=packet_info.src_ip,
                timestamp=current_time
            )
        
        return None

class DnsAmplificationDetector(BaseDetectionModule):
    """Detects DNS amplification attacks"""
    
    def __init__(self, config: dict):
        super().__init__(config, 'dns_amplification')
        self.response_size_threshold = config['detection']['dns_amplification']['dns_response_size_threshold']
        self.qps_threshold = config['detection']['dns_amplification']['dns_qps_threshold']
        self.amplification_ratio = config['detection']['dns_amplification']['amplification_ratio']
        
    def analyze_packet(self, packet_info, ip_stats) -> Optional[DetectionResult]:
        if not self.is_enabled() or packet_info.protocol != "UDP":
            return None
        
        # Check for large DNS responses
        if packet_info.dns_response_size > self.response_size_threshold:
            # Calculate potential amplification
            query_size = 50  # Typical DNS query size
            amplification = packet_info.dns_response_size / query_size
            
            if amplification > self.amplification_ratio:
                score = min(100, int((amplification / self.amplification_ratio) * 40))
                confidence = 0.9
                
                details = f"DNS response size: {packet_info.dns_response_size} bytes, " \
                         f"amplification: {amplification:.1f}x"
                
                return DetectionResult(
                    threat_type="DNS_AMPLIFICATION",
                    score=score,
                    confidence=confidence,
                    details=details,
                    source_ip=packet_info.src_ip,
                    timestamp=packet_info.timestamp
                )
        
        return None

class AnomalyDetector(BaseDetectionModule):
    """Statistical anomaly detection using EWMA and Z-score"""
    
    def __init__(self, config: dict):
        super().__init__(config, 'anomaly')
        self.zscore_threshold = config['detection']['anomaly']['zscore_threshold']
        self.ewma_alpha = config['detection']['anomaly']['ewma_alpha']
        self.min_samples = config['detection']['anomaly']['min_samples']
        
        # Statistical tracking per IP
        self.baselines: Dict[str, Dict] = {}
        
    def analyze_packet(self, packet_info, ip_stats) -> Optional[DetectionResult]:
        if not self.is_enabled():
            return None
        
        src_ip = packet_info.src_ip
        current_time = packet_info.timestamp
        
        # Initialize baseline for new IPs
        if src_ip not in self.baselines:
            self.baselines[src_ip] = {
                'packet_rates': deque(maxlen=1000),
                'ewma_rate': 0.0,
                'ewma_variance': 0.0,
                'sample_count': 0
            }
        
        baseline = self.baselines[src_ip]
        
        # Calculate current packet rate (packets per second)
        window_size = 10  # 10-second window
        recent_packets = len([t for t in ip_stats.packet_timestamps 
                            if current_time - t <= window_size])
        current_rate = recent_packets / window_size
        
        baseline['packet_rates'].append(current_rate)
        baseline['sample_count'] += 1
        
        # Need minimum samples for reliable detection
        if baseline['sample_count'] < self.min_samples:
            return None
        
        # Update EWMA
        if baseline['ewma_rate'] == 0:
            baseline['ewma_rate'] = current_rate
        else:
            baseline['ewma_rate'] = (self.ewma_alpha * current_rate + 
                                   (1 - self.ewma_alpha) * baseline['ewma_rate'])
        
        # Calculate variance
        if len(baseline['packet_rates']) > 1:
            variance = statistics.variance(baseline['packet_rates'])
            if baseline['ewma_variance'] == 0:
                baseline['ewma_variance'] = variance
            else:
                baseline['ewma_variance'] = (self.ewma_alpha * variance + 
                                           (1 - self.ewma_alpha) * baseline['ewma_variance'])
        
        # Calculate Z-score
        if baseline['ewma_variance'] > 0:
            std_dev = math.sqrt(baseline['ewma_variance'])
            zscore = abs(current_rate - baseline['ewma_rate']) / std_dev
            
            if zscore > self.zscore_threshold:
                score = min(100, int((zscore / self.zscore_threshold) * 15))
                confidence = min(1.0, zscore / (self.zscore_threshold * 2))
                
                details = f"Packet rate: {current_rate:.1f} pps, " \
                         f"baseline: {baseline['ewma_rate']:.1f} pps, " \
                         f"Z-score: {zscore:.2f}"
                
                return DetectionResult(
                    threat_type="ANOMALY",
                    score=score,
                    confidence=confidence,
                    details=details,
                    source_ip=src_ip,
                    timestamp=current_time
                )
        
        return None

class ThreatIntelDetector(BaseDetectionModule):
    """Threat intelligence based detection"""
    
    def __init__(self, config: dict):
        super().__init__(config, 'threat_intel')
        self.threat_ips = set()
        self.load_threat_intel()
        
    def load_threat_intel(self):
        """Load threat intelligence feeds"""
        # This would load from external feeds in production
        # For now, we'll use a static list
        self.threat_ips = {
            "192.168.1.100",  # Example malicious IP
            "10.0.0.50",      # Example malicious IP
        }
        
    def analyze_packet(self, packet_info, ip_stats) -> Optional[DetectionResult]:
        if not self.is_enabled():
            return None
        
        if packet_info.src_ip in self.threat_ips:
            return DetectionResult(
                threat_type="THREAT_INTEL",
                score=50,  # High score for known bad IPs
                confidence=1.0,
                details=f"IP found in threat intelligence feed",
                source_ip=packet_info.src_ip,
                timestamp=packet_info.timestamp
            )
        
        return None

class DetectionEngine:
    """Main detection engine that coordinates all detection modules"""
    
    def __init__(self, config: dict):
        self.config = config
        self.detection_modules = []
        self.results_callbacks = []
        
        # Initialize detection modules
        self._initialize_modules()
        
        logger.info(f"Detection engine initialized with {len(self.detection_modules)} modules")
    
    def _initialize_modules(self):
        """Initialize all detection modules"""
        self.detection_modules = [
            SynFloodDetector(self.config),
            UdpFloodDetector(self.config),
            IcmpFloodDetector(self.config),
            PortScanDetector(self.config),
            HttpFloodDetector(self.config),
            DnsAmplificationDetector(self.config),
            AnomalyDetector(self.config),
            ThreatIntelDetector(self.config),
        ]
        
        # Log enabled modules
        enabled_modules = [m.name for m in self.detection_modules if m.is_enabled()]
        logger.info(f"Enabled detection modules: {enabled_modules}")
    
    def analyze_packet(self, packet_info, ip_stats) -> List[DetectionResult]:
        """Run all detection modules on a packet"""
        results = []
        
        for module in self.detection_modules:
            try:
                result = module.analyze_packet(packet_info, ip_stats)
                if result:
                    results.append(result)
                    logger.debug(f"Detection: {result}")
            except Exception as e:
                logger.error(f"Error in detection module {module.name}: {e}")
        
        # Notify callbacks
        for result in results:
            for callback in self.results_callbacks:
                try:
                    callback(result)
                except Exception as e:
                    logger.error(f"Error in detection callback: {e}")
        
        return results
    
    def add_result_callback(self, callback):
        """Add callback function for detection results"""
        self.results_callbacks.append(callback)
    
    def get_module_stats(self) -> Dict[str, dict]:
        """Get statistics from all detection modules"""
        stats = {}
        for module in self.detection_modules:
            stats[module.name] = {
                'enabled': module.is_enabled(),
                'type': type(module).__name__
            }
        return stats

if __name__ == "__main__":
    # Test detection modules
    import yaml
    
    config_path = "/workspaces/codespaces-blank/network-security-agent/config/security_agent.yaml"
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    engine = DetectionEngine(config)
    print(f"Detection engine initialized with modules: {[m.name for m in engine.detection_modules]}")
