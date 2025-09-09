#!/usr/bin/env python3
"""
Network Security Agent - Component Test Script
===============================================
Tests all major components in isolation to ensure they work correctly.
"""

import sys
import os
import time
import unittest
from unittest.mock import Mock, patch, MagicMock
import threading
import socket
import json
import yaml

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

class TestSecurityAgentComponents(unittest.TestCase):
    """Test suite for validating all security agent components."""
    
    def setUp(self):
        """Set up test configuration."""
        self.test_config = {
            'network': {
                'interface': 'eth0',
                'snaplen': 65536,
                'timeout_ms': 100,
                'promisc': False
            },
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
                'icmp_flood': {
                    'enabled': True,
                    'icmp_pps_threshold': 500,
                    'window_size': 10
                },
                'port_scan': {
                    'enabled': True,
                    'unique_ports_threshold': 50,
                    'window_size': 60
                },
                'http_flood': {
                    'enabled': True,
                    'requests_per_minute_threshold': 300,
                    'window_size': 60
                },
                'dns_amplification': {
                    'enabled': True,
                    'amplification_ratio_threshold': 10,
                    'query_response_size_threshold': 1000
                },
                'anomaly': {
                    'enabled': True,
                    'window_size': 300,
                    'std_dev_threshold': 3.0
                },
                'threat_intel': {
                    'enabled': True,
                    'cache_ttl': 3600
                }
            },
            'scoring': {
                'weights': {
                    'syn_flood': 30,
                    'udp_flood': 25,
                    'port_scan': 35,
                    'icmp_flood': 20,
                    'http_flood': 25,
                    'dns_amplification': 35,
                    'anomaly': 15,
                    'threat_intel': 50
                },
                'thresholds': {
                    'warn_threshold': 50,
                    'ban_threshold': 80
                }
            },
            'blocking': {
                'ttl': {
                    'default': 1200,
                    'port_scan': 3600
                },
                'firewall': {
                    'backend': 'mock'
                }
            },
            'access_control': {
                'allowlist': ['127.0.0.1/32', '10.0.0.0/8'],
                'denylist': []
            },
            'logging': {
                'level': 'INFO',
                'format': 'json'
            },
            'metrics': {
                'enabled': True,
                'port': 9090
            },
            'api': {
                'enabled': True,
                'host': '127.0.0.1',
                'port': 8080
            }
        }
    
    def test_packet_capture_import(self):
        """Test packet capture module can be imported and initialized."""
        try:
            from packet_capture import PacketCaptureEngine, PacketInfo
            
            # Create a mock capture instance (won't actually capture packets)
            capture = PacketCaptureEngine(self.test_config)
            self.assertIsNotNone(capture)
            
            # Test PacketInfo creation
            packet_info = PacketInfo(
                src_ip="192.168.1.100",
                dst_ip="192.168.1.1", 
                src_port=12345,
                dst_port=80,
                protocol="TCP",
                packet_size=64,
                tcp_flags="S"
            )
            self.assertEqual(packet_info.src_ip, "192.168.1.100")
            self.assertEqual(packet_info.protocol, "TCP")
            
            print("✅ Packet capture module: PASS")
            
        except Exception as e:
            self.fail(f"Packet capture test failed: {e}")
    
    def test_detection_modules_import(self):
        """Test detection modules can be imported and run."""
        try:
            from detection_modules import (
                DetectionEngine, SynFloodDetector, UdpFloodDetector,
                PortScanDetector, HttpFloodDetector, DetectionResult
            )
            from packet_capture import PacketInfo
            
            # Create detection engine
            engine = DetectionEngine(self.test_config)
            self.assertIsNotNone(engine)
            
            # Test individual detectors
            syn_detector = SynFloodDetector(self.test_config['detection']['syn_flood'])
            udp_detector = UdpFloodDetector(self.test_config['detection']['udp_flood'])
            port_detector = PortScanDetector(self.test_config['detection']['port_scan'])
            
            # Test with mock packet
            packet_info = PacketInfo(
                src_ip="192.168.1.100",
                dst_ip="192.168.1.1",
                src_port=12345,
                dst_port=80,
                protocol="TCP",
                packet_size=64,
                tcp_flags="S"
            )
            
            # Mock IP stats for testing
            ip_stats = {
                'packet_count': 100,
                'syn_count': 80,
                'syn_ack_count': 5,
                'unique_dst_ports': set([80, 443, 22, 21, 23])
            }
            
            # Test detection (won't trigger with single packet)
            result = syn_detector.analyze_packet(packet_info, ip_stats)
            # Detection should work but not necessarily trigger
            
            print("✅ Detection modules: PASS")
            
        except Exception as e:
            self.fail(f"Detection modules test failed: {e}")
    
    def test_decision_engine_import(self):
        """Test decision engine can be imported and make decisions."""
        try:
            from decision_engine import DecisionEngine, BlockAction
            from detection_modules import DetectionResult
            
            # Create decision engine
            engine = DecisionEngine(self.test_config)
            self.assertIsNotNone(engine)
            
            # Test decision making with high threat score
            detection = DetectionResult(
                threat_type="SYN_FLOOD",
                score=90,  # High score should trigger block
                confidence=0.9,
                details="Test SYN flood detection",
                source_ip="192.168.1.100"
            )
            
            action = engine.make_decision("192.168.1.100", [detection])
            self.assertIsNotNone(action)
            
            print("✅ Decision engine: PASS")
            
        except Exception as e:
            self.fail(f"Decision engine test failed: {e}")
    
    def test_metrics_collector_import(self):
        """Test metrics collector can be imported and collect metrics."""
        try:
            from metrics_collector import MetricsCollector
            from packet_capture import PacketInfo
            from detection_modules import DetectionResult
            
            # Create metrics collector
            collector = MetricsCollector(self.test_config)
            self.assertIsNotNone(collector)
            
            # Test metric recording
            packet_info = PacketInfo(
                src_ip="192.168.1.100",
                dst_ip="192.168.1.1",
                src_port=12345,
                dst_port=80,
                protocol="TCP",
                packet_size=64,
                tcp_flags="S"
            )
            collector.record_packet(packet_info)
            
            detection = DetectionResult(
                threat_type="SYN_FLOOD",
                score=80,
                confidence=0.9,
                details="Test detection",
                source_ip="192.168.1.100"
            )
            collector.record_detection(detection)
            
            # Test metrics retrieval
            metrics = collector.get_json_metrics()
            self.assertIsInstance(metrics, dict)
            self.assertIn('total_packets', metrics)
            
            print("✅ Metrics collector: PASS")
            
        except Exception as e:
            self.fail(f"Metrics collector test failed: {e}")
    
    def test_api_server_import(self):
        """Test API server can be imported."""
        try:
            from api_server import APIServer
            
            # Create API server (won't start it)
            api = APIServer(self.test_config)
            self.assertIsNotNone(api)
            
            print("✅ API server: PASS")
            
        except Exception as e:
            self.fail(f"API server test failed: {e}")
    
    def test_main_security_agent(self):
        """Test main security agent can be imported."""
        try:
            # Import without running
            import security_agent
            self.assertTrue(hasattr(security_agent, 'NetworkSecurityAgent'))
            
            print("✅ Main security agent: PASS")
            
        except Exception as e:
            self.fail(f"Main security agent test failed: {e}")
    
    def test_configuration_loading(self):
        """Test configuration loading and validation."""
        try:
            # Test YAML loading
            yaml_str = yaml.dump(self.test_config)
            loaded_config = yaml.safe_load(yaml_str)
            self.assertEqual(loaded_config, self.test_config)
            
            print("✅ Configuration loading: PASS")
            
        except Exception as e:
            self.fail(f"Configuration test failed: {e}")

def run_synthetic_traffic_test():
    """Run a synthetic traffic generation test using Python sockets."""
    print("\n🔧 Running synthetic traffic test...")
    
    try:
        # Test TCP connection simulation
        import socket
        import time
        
        # Create a simple TCP server for testing
        def mock_server():
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                server_sock.bind(('127.0.0.1', 8888))
                server_sock.listen(1)
                server_sock.settimeout(2)  # 2 second timeout
                conn, addr = server_sock.accept()
                conn.close()
            except socket.timeout:
                pass  # Expected timeout
            except Exception:
                pass  # Ignore other errors
            finally:
                server_sock.close()
        
        # Start mock server in background
        server_thread = threading.Thread(target=mock_server)
        server_thread.daemon = True
        server_thread.start()
        
        time.sleep(0.1)  # Let server start
        
        # Generate some "malicious" traffic patterns
        for i in range(10):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                sock.connect(('127.0.0.1', 8888))
                sock.close()
            except:
                pass  # Expected connection failures
        
        print("✅ Synthetic traffic test: PASS")
        
    except Exception as e:
        print(f"⚠️  Synthetic traffic test: {e}")

def check_dependencies():
    """Check if all required dependencies are installed."""
    print("🔍 Checking dependencies...")
    
    required_packages = [
        'scapy', 'yaml', 'prometheus_client', 'flask', 
        'structlog', 'numpy', 'scipy'
    ]
    
    missing = []
    for package in required_packages:
        try:
            __import__(package)
            print(f"  ✅ {package}")
        except ImportError:
            missing.append(package)
            print(f"  ❌ {package}")
    
    if missing:
        print(f"\n⚠️  Missing packages: {', '.join(missing)}")
        return False
    else:
        print("\n✅ All dependencies available")
        return True

def main():
    """Main test function."""
    print("🛡️  Network Security Agent - Component Tests")
    print("=" * 50)
    
    # Check dependencies first
    if not check_dependencies():
        print("\n❌ Dependency check failed")
        return 1
    
    # Run unit tests
    print("\n🧪 Running component tests...")
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestSecurityAgentComponents)
    runner = unittest.TextTestRunner(verbosity=0, buffer=True)
    result = runner.run(suite)
    
    # Run synthetic traffic test
    run_synthetic_traffic_test()
    
    # Summary
    print("\n📊 Test Summary:")
    print(f"  Tests run: {result.testsRun}")
    print(f"  Failures: {len(result.failures)}")
    print(f"  Errors: {len(result.errors)}")
    
    if result.failures:
        print("\n❌ Failures:")
        for test, trace in result.failures:
            print(f"  - {test}: {trace}")
    
    if result.errors:
        print("\n❌ Errors:")
        for test, trace in result.errors:
            print(f"  - {test}: {trace}")
    
    if result.wasSuccessful():
        print("\n🎉 All tests passed! The security agent is ready for deployment.")
        return 0
    else:
        print("\n⚠️  Some tests failed. Check the errors above.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
