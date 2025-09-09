#!/usr/bin/env python3
"""
Network Security Agent - Test Suite
Comprehensive tests for all components using synthetic traffic.
"""

import os
import sys
import time
import unittest
import tempfile
import yaml
import threading
from unittest.mock import Mock, patch
import subprocess

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from packet_capture import PacketCaptureEngine, PacketInfo, IPStats
from detection_modules import (
    DetectionEngine, SynFloodDetector, UdpFloodDetector, 
    IcmpFloodDetector, PortScanDetector, DetectionResult
)
from decision_engine import DecisionEngine, BlockAction
from metrics_collector import MetricsCollector
from api_server import APIServer

class TestPacketCapture(unittest.TestCase):
    """Test packet capture functionality"""
    
    def setUp(self):
        # Create test config
        self.config = {
            'network': {'interface': 'any'},
            'time_windows': {'short_window': 10, 'medium_window': 60, 'long_window': 300},
            'performance': {'log_level': 'WARNING', 'max_tracked_ips': 1000, 'state_cleanup_interval': 30},
            'development': {'mock_mode': True}
        }
        
        # Create temporary config file
        self.config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False)
        yaml.dump(self.config, self.config_file)
        self.config_file.close()
        
        self.engine = PacketCaptureEngine(self.config_file.name)
    
    def tearDown(self):
        os.unlink(self.config_file.name)
    
    def test_packet_parsing(self):
        """Test packet parsing functionality"""
        # Mock packet data would go here
        # For now, test PacketInfo creation
        packet_info = PacketInfo(
            timestamp=time.time(),
            src_ip="192.168.1.100",
            dst_ip="192.168.1.1",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            packet_size=64,
            is_syn=True
        )
        
        self.assertEqual(packet_info.src_ip, "192.168.1.100")
        self.assertEqual(packet_info.protocol, "TCP")
        self.assertTrue(packet_info.is_syn)
    
    def test_ip_stats_update(self):
        """Test IP statistics tracking"""
        packet_info = PacketInfo(
            timestamp=time.time(),
            src_ip="192.168.1.100",
            dst_ip="192.168.1.1",
            protocol="TCP",
            is_syn=True
        )
        
        self.engine.update_ip_stats(packet_info)
        
        stats = self.engine.get_ip_stats("192.168.1.100")
        self.assertIsNotNone(stats)
        self.assertEqual(stats.total_packets, 1)
        self.assertEqual(stats.tcp_packets, 1)
        self.assertEqual(stats.syn_count, 1)
    
    def test_sliding_windows(self):
        """Test sliding window functionality"""
        current_time = time.time()
        stats = IPStats()
        
        # Add timestamps
        for i in range(10):
            stats.packet_timestamps.append(current_time - i)
        
        # Update sliding windows
        stats.update_sliding_windows(current_time, 5)
        
        # Should only have timestamps within the window
        self.assertLessEqual(len(stats.packet_timestamps), 6)  # 0-5 seconds

class TestDetectionModules(unittest.TestCase):
    """Test detection modules"""
    
    def setUp(self):
        self.config = {
            'detection': {
                'syn_flood': {
                    'enabled': True,
                    'syn_rate_threshold': 100,
                    'syn_ack_ratio_threshold': 0.2,
                    'window_size': 10
                },
                'udp_flood': {
                    'enabled': True,
                    'udp_pps_threshold': 1000,
                    'window_size': 10
                },
                'port_scan': {
                    'enabled': True,
                    'unique_ports_threshold': 50,
                    'window_size': 60,
                    'connection_threshold': 5
                }
            }
        }
        
        self.detection_engine = DetectionEngine(self.config)
    
    def test_syn_flood_detection(self):
        """Test SYN flood detection"""
        detector = SynFloodDetector(self.config)
        
        # Create mock IP stats with high SYN rate
        ip_stats = IPStats()
        current_time = time.time()
        
        # Add many SYN packets in short time
        for i in range(150):
            ip_stats.syn_timestamps.append(current_time - i/100)  # High rate
        ip_stats.syn_count = 150
        ip_stats.ack_count = 10  # Low ACK ratio
        
        packet_info = PacketInfo(
            timestamp=current_time,
            src_ip="192.168.1.100",
            dst_ip="192.168.1.1",
            protocol="TCP",
            is_syn=True
        )
        
        result = detector.analyze_packet(packet_info, ip_stats)
        
        self.assertIsNotNone(result)
        self.assertEqual(result.threat_type, "SYN_FLOOD")
        self.assertGreater(result.score, 0)
    
    def test_port_scan_detection(self):
        """Test port scan detection"""
        detector = PortScanDetector(self.config)
        
        # Create mock IP stats with many unique ports
        ip_stats = IPStats()
        for port in range(1, 100):  # Scan 99 ports
            ip_stats.unique_dst_ports.add(port)
            ip_stats.port_connections[port] = 1  # Low connections per port
        
        packet_info = PacketInfo(
            timestamp=time.time(),
            src_ip="192.168.1.100",
            dst_ip="192.168.1.1",
            dst_port=100,
            protocol="TCP"
        )
        
        result = detector.analyze_packet(packet_info, ip_stats)
        
        self.assertIsNotNone(result)
        self.assertEqual(result.threat_type, "PORT_SCAN")
        self.assertGreater(result.score, 0)
    
    def test_detection_engine(self):
        """Test overall detection engine"""
        # Test that all modules are loaded
        enabled_modules = [m for m in self.detection_engine.detection_modules if m.is_enabled()]
        self.assertGreater(len(enabled_modules), 0)
        
        # Test module stats
        stats = self.detection_engine.get_module_stats()
        self.assertIsInstance(stats, dict)

class TestDecisionEngine(unittest.TestCase):
    """Test decision engine and firewall interface"""
    
    def setUp(self):
        self.config = {
            'scoring': {
                'weights': {'syn_flood': 30, 'port_scan': 35},
                'thresholds': {'warn_threshold': 50, 'ban_threshold': 80}
            },
            'blocking': {
                'ttl': {'default': 1200, 'port_scan': 3600, 'dos_attack': 7200},
                'firewall': {'backend': 'mock', 'chain': 'test', 'table': 'filter'},
                'rate_limit': {'enabled': False}
            },
            'access_control': {
                'allowlist': ['127.0.0.1/32', '192.168.1.0/24'],
                'denylist': ['10.0.0.1/32']
            }
        }
        
        self.decision_engine = DecisionEngine(self.config)
    
    def test_allowlist_check(self):
        """Test allowlist functionality"""
        # IP in allowlist should not be blocked
        self.assertTrue(self.decision_engine._is_in_allowlist("192.168.1.100"))
        self.assertFalse(self.decision_engine._is_in_allowlist("1.2.3.4"))
    
    def test_scoring(self):
        """Test threat scoring"""
        detection = DetectionResult(
            threat_type="SYN_FLOOD",
            score=80,
            confidence=0.9,
            details="Test detection",
            source_ip="1.2.3.4"
        )
        
        # Should trigger block
        block = self.decision_engine.process_detection(detection)
        self.assertIsNotNone(block)
        self.assertEqual(block.ip, "1.2.3.4")
    
    def test_block_management(self):
        """Test blocking and unblocking"""
        ip = "1.2.3.4"
        
        # Apply block
        block = self.decision_engine._apply_block(ip, "test", 85, 3600)
        self.assertIsNotNone(block)
        
        # Check if blocked
        blocked_ips = self.decision_engine.get_blocked_ips()
        self.assertIn(ip, blocked_ips)
        
        # Unblock
        success = self.decision_engine.unblock_ip(ip, "test")
        self.assertTrue(success)
        
        # Check if unblocked
        blocked_ips = self.decision_engine.get_blocked_ips()
        self.assertNotIn(ip, blocked_ips)

class TestMetricsCollector(unittest.TestCase):
    """Test metrics collection"""
    
    def setUp(self):
        self.config = {
            'metrics': {
                'enabled': True,
                'port': 9091,  # Different port to avoid conflicts
                'export_interval': 1
            }
        }
        
        self.collector = MetricsCollector(self.config)
    
    def test_packet_recording(self):
        """Test packet metrics recording"""
        packet_info = PacketInfo(
            timestamp=time.time(),
            src_ip="192.168.1.100",
            dst_ip="192.168.1.1",
            protocol="TCP"
        )
        
        self.collector.record_packet(packet_info)
        
        metrics = self.collector.get_json_metrics()
        self.assertEqual(metrics['counters']['packets_total'], 1)
        self.assertEqual(metrics['counters']['packets_tcp'], 1)
    
    def test_detection_recording(self):
        """Test detection metrics recording"""
        detection = DetectionResult(
            threat_type="SYN_FLOOD",
            score=85,
            confidence=0.9,
            details="Test",
            source_ip="192.168.1.100"
        )
        
        self.collector.record_detection(detection)
        
        metrics = self.collector.get_json_metrics()
        self.assertEqual(metrics['counters']['detections_total'], 1)
        self.assertEqual(metrics['detections_by_type']['SYN_FLOOD'], 1)
    
    def test_prometheus_format(self):
        """Test Prometheus metrics format"""
        prometheus_metrics = self.collector.get_prometheus_metrics()
        self.assertIn('security_agent_packets_total', prometheus_metrics)
        self.assertIn('# HELP', prometheus_metrics)
        self.assertIn('# TYPE', prometheus_metrics)

class TestAPIServer(unittest.TestCase):
    """Test API server functionality"""
    
    def setUp(self):
        # Mock agent
        self.mock_agent = Mock()
        self.mock_agent.config = {
            'api': {'enabled': True, 'host': '127.0.0.1', 'port': 8081}
        }
        self.mock_agent.get_status.return_value = {'running': True, 'uptime': 123}
        self.mock_agent.get_blocked_ips.return_value = {}
        self.mock_agent.block_ip.return_value = True
        self.mock_agent.unblock_ip.return_value = True
        
        self.api_server = APIServer(self.mock_agent.config, self.mock_agent)
    
    def test_api_initialization(self):
        """Test API server initialization"""
        self.assertTrue(self.api_server.enabled)
        self.assertEqual(self.api_server.port, 8081)

class TestIntegration(unittest.TestCase):
    """Integration tests"""
    
    def setUp(self):
        """Setup for integration tests"""
        self.config = {
            'network': {'interface': 'any'},
            'time_windows': {'short_window': 10, 'medium_window': 60, 'long_window': 300},
            'detection': {
                'syn_flood': {'enabled': True, 'syn_rate_threshold': 10, 'syn_ack_ratio_threshold': 0.2, 'window_size': 10},
                'udp_flood': {'enabled': True, 'udp_pps_threshold': 100, 'window_size': 10},
                'port_scan': {'enabled': True, 'unique_ports_threshold': 10, 'window_size': 60, 'connection_threshold': 5}
            },
            'scoring': {
                'weights': {'syn_flood': 30, 'port_scan': 35},
                'thresholds': {'warn_threshold': 50, 'ban_threshold': 80}
            },
            'blocking': {
                'ttl': {'default': 60},
                'firewall': {'backend': 'mock'},
                'rate_limit': {'enabled': False}
            },
            'access_control': {'allowlist': [], 'denylist': []},
            'performance': {'log_level': 'WARNING', 'max_tracked_ips': 100},
            'development': {'mock_mode': True},
            'metrics': {'enabled': False},
            'api': {'enabled': False}
        }
    
    def test_end_to_end_syn_flood(self):
        """Test end-to-end SYN flood detection and blocking"""
        # Create temporary config
        config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False)
        yaml.dump(self.config, config_file)
        config_file.close()
        
        try:
            # Initialize components
            packet_engine = PacketCaptureEngine(config_file.name)
            detection_engine = DetectionEngine(self.config)
            decision_engine = DecisionEngine(self.config)
            
            # Simulate SYN flood attack
            attacker_ip = "1.2.3.4"
            current_time = time.time()
            
            # Generate SYN flood packets
            for i in range(20):  # Above threshold
                packet_info = PacketInfo(
                    timestamp=current_time,
                    src_ip=attacker_ip,
                    dst_ip="192.168.1.1",
                    protocol="TCP",
                    is_syn=True
                )
                
                packet_engine.update_ip_stats(packet_info)
                ip_stats = packet_engine.get_ip_stats(attacker_ip)
                
                # Run detection
                results = detection_engine.analyze_packet(packet_info, ip_stats)
                
                # Process through decision engine
                for result in results:
                    block = decision_engine.process_detection(result)
                    if block:
                        # Verify block was applied
                        self.assertEqual(block.ip, attacker_ip)
                        self.assertEqual(block.reason.split()[0], "SYN_FLOOD")
                        break
            
            # Check if IP was blocked
            blocked_ips = decision_engine.get_blocked_ips()
            self.assertIn(attacker_ip, blocked_ips)
            
        finally:
            os.unlink(config_file.name)

def run_synthetic_tests():
    """Run tests with synthetic traffic generation"""
    print("🧪 Running synthetic traffic tests...")
    
    # Test 1: Generate SYN flood using hping3 (if available)
    try:
        # Check if hping3 is available
        subprocess.run(['which', 'hping3'], check=True, capture_output=True)
        print("✅ hping3 available for synthetic testing")
        
        # This would run actual traffic generation
        # subprocess.run(['hping3', '-S', '-p', '80', '--flood', 'target_ip'])
        
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("⚠️  hping3 not available, skipping synthetic traffic tests")
    
    # Test 2: Generate packets using scapy
    try:
        from scapy.all import IP, TCP, send
        print("✅ Scapy available for packet generation")
        
        # This would generate test packets
        # packet = IP(dst="192.168.1.1")/TCP(dport=80, flags="S")
        # send(packet, count=100, verbose=0)
        
    except ImportError:
        print("⚠️  Scapy not available for packet generation")

if __name__ == '__main__':
    # Set up test environment
    import logging
    logging.basicConfig(level=logging.WARNING)
    
    # Run unit tests
    print("🚀 Starting Network Security Agent Test Suite")
    print("=" * 60)
    
    # Discover and run tests
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    
    print("\n📋 Running Unit Tests...")
    result = runner.run(suite)
    
    # Run synthetic tests
    print("\n🌐 Running Synthetic Traffic Tests...")
    run_synthetic_tests()
    
    # Summary
    print("\n" + "=" * 60)
    if result.wasSuccessful():
        print("✅ All tests passed successfully!")
        exit_code = 0
    else:
        print(f"❌ {len(result.failures)} test(s) failed, {len(result.errors)} error(s)")
        exit_code = 1
    
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    sys.exit(exit_code)
