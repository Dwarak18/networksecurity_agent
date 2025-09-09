#!/usr/bin/env python3
"""
Network Security Agent - Metrics Collector
Collects and exports metrics for monitoring and observability.
"""

import time
import threading
from collections import defaultdict, deque
from typing import Dict, List, Optional
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

logger = logging.getLogger(__name__)

class MetricsCollector:
    """Collects and exports metrics for the security agent"""
    
    def __init__(self, config: dict):
        self.config = config
        self.metrics_config = config.get('metrics', {})
        self.enabled = self.metrics_config.get('enabled', True)
        
        if not self.enabled:
            logger.info("Metrics collection disabled")
            return
        
        # Metrics storage
        self.metrics = {
            # Counter metrics
            'packets_total': 0,
            'packets_tcp': 0,
            'packets_udp': 0,
            'packets_icmp': 0,
            'detections_total': 0,
            'blocks_total': 0,
            'false_positives_total': 0,
            
            # Gauge metrics
            'active_blocks': 0,
            'tracked_ips': 0,
            
            # Detection type counters
            'detections_by_type': defaultdict(int),
            
            # Time series data (last 1000 points)
            'packet_rate_history': deque(maxlen=1000),
            'detection_rate_history': deque(maxlen=1000),
            'block_rate_history': deque(maxlen=1000),
            
            # Response times
            'detection_latency_ms': deque(maxlen=1000),
            'block_latency_ms': deque(maxlen=1000),
        }
        
        self.metrics_lock = threading.Lock()
        
        # HTTP server for metrics endpoint
        self.http_server = None
        self.server_thread = None
        
        # Export interval
        self.export_interval = self.metrics_config.get('export_interval', 60)
        self.last_export = time.time()
        
        logger.info("Metrics collector initialized")
    
    def record_packet(self, packet_info):
        """Record packet metrics"""
        if not self.enabled:
            return
        
        with self.metrics_lock:
            self.metrics['packets_total'] += 1
            
            if packet_info.protocol == 'TCP':
                self.metrics['packets_tcp'] += 1
            elif packet_info.protocol == 'UDP':
                self.metrics['packets_udp'] += 1
            elif packet_info.protocol == 'ICMP':
                self.metrics['packets_icmp'] += 1
    
    def record_detection(self, detection_result, block_action=None):
        """Record detection metrics"""
        if not self.enabled:
            return
        
        detection_time = time.time()
        
        with self.metrics_lock:
            self.metrics['detections_total'] += 1
            self.metrics['detections_by_type'][detection_result.threat_type] += 1
            
            # Record detection latency
            detection_latency = (detection_time - detection_result.timestamp) * 1000
            self.metrics['detection_latency_ms'].append(detection_latency)
            
            if block_action:
                self.metrics['blocks_total'] += 1
                
                # Record block latency
                block_latency = (time.time() - detection_time) * 1000
                self.metrics['block_latency_ms'].append(block_latency)
    
    def update_gauge_metrics(self, active_blocks: int, tracked_ips: int):
        """Update gauge metrics"""
        if not self.enabled:
            return
        
        with self.metrics_lock:
            self.metrics['active_blocks'] = active_blocks
            self.metrics['tracked_ips'] = tracked_ips
    
    def export_time_series(self):
        """Export time series metrics"""
        if not self.enabled:
            return
        
        current_time = time.time()
        
        # Only export at specified intervals
        if current_time - self.last_export < self.export_interval:
            return
        
        with self.metrics_lock:
            # Calculate rates since last export
            time_delta = current_time - self.last_export
            
            packet_rate = self.metrics['packets_total'] / time_delta if time_delta > 0 else 0
            detection_rate = self.metrics['detections_total'] / time_delta if time_delta > 0 else 0
            block_rate = self.metrics['blocks_total'] / time_delta if time_delta > 0 else 0
            
            # Add to history
            self.metrics['packet_rate_history'].append({
                'timestamp': current_time,
                'value': packet_rate
            })
            
            self.metrics['detection_rate_history'].append({
                'timestamp': current_time,
                'value': detection_rate
            })
            
            self.metrics['block_rate_history'].append({
                'timestamp': current_time,
                'value': block_rate
            })
            
            self.last_export = current_time
    
    def get_prometheus_metrics(self) -> str:
        """Generate Prometheus format metrics"""
        if not self.enabled:
            return ""
        
        lines = []
        
        with self.metrics_lock:
            # Counter metrics
            lines.append('# HELP security_agent_packets_total Total number of packets processed')
            lines.append('# TYPE security_agent_packets_total counter')
            lines.append(f'security_agent_packets_total {self.metrics["packets_total"]}')
            
            lines.append('# HELP security_agent_packets_by_protocol_total Packets by protocol')
            lines.append('# TYPE security_agent_packets_by_protocol_total counter')
            lines.append(f'security_agent_packets_by_protocol_total{{protocol="tcp"}} {self.metrics["packets_tcp"]}')
            lines.append(f'security_agent_packets_by_protocol_total{{protocol="udp"}} {self.metrics["packets_udp"]}')
            lines.append(f'security_agent_packets_by_protocol_total{{protocol="icmp"}} {self.metrics["packets_icmp"]}')
            
            lines.append('# HELP security_agent_detections_total Total number of detections')
            lines.append('# TYPE security_agent_detections_total counter')
            lines.append(f'security_agent_detections_total {self.metrics["detections_total"]}')
            
            lines.append('# HELP security_agent_blocks_total Total number of IP blocks')
            lines.append('# TYPE security_agent_blocks_total counter')
            lines.append(f'security_agent_blocks_total {self.metrics["blocks_total"]}')
            
            # Detection by type
            lines.append('# HELP security_agent_detections_by_type_total Detections by threat type')
            lines.append('# TYPE security_agent_detections_by_type_total counter')
            for threat_type, count in self.metrics['detections_by_type'].items():
                lines.append(f'security_agent_detections_by_type_total{{type="{threat_type.lower()}"}} {count}')
            
            # Gauge metrics
            lines.append('# HELP security_agent_active_blocks Current number of active IP blocks')
            lines.append('# TYPE security_agent_active_blocks gauge')
            lines.append(f'security_agent_active_blocks {self.metrics["active_blocks"]}')
            
            lines.append('# HELP security_agent_tracked_ips Current number of tracked IPs')
            lines.append('# TYPE security_agent_tracked_ips gauge')
            lines.append(f'security_agent_tracked_ips {self.metrics["tracked_ips"]}')
            
            # Latency metrics
            if self.metrics['detection_latency_ms']:
                avg_detection_latency = sum(self.metrics['detection_latency_ms']) / len(self.metrics['detection_latency_ms'])
                lines.append('# HELP security_agent_detection_latency_ms Average detection latency in milliseconds')
                lines.append('# TYPE security_agent_detection_latency_ms gauge')
                lines.append(f'security_agent_detection_latency_ms {avg_detection_latency:.2f}')
            
            if self.metrics['block_latency_ms']:
                avg_block_latency = sum(self.metrics['block_latency_ms']) / len(self.metrics['block_latency_ms'])
                lines.append('# HELP security_agent_block_latency_ms Average block latency in milliseconds')
                lines.append('# TYPE security_agent_block_latency_ms gauge')
                lines.append(f'security_agent_block_latency_ms {avg_block_latency:.2f}')
        
        return '\n'.join(lines) + '\n'
    
    def get_json_metrics(self) -> dict:
        """Get metrics in JSON format"""
        if not self.enabled:
            return {}
        
        with self.metrics_lock:
            # Calculate averages for latency metrics
            avg_detection_latency = 0
            if self.metrics['detection_latency_ms']:
                avg_detection_latency = sum(self.metrics['detection_latency_ms']) / len(self.metrics['detection_latency_ms'])
            
            avg_block_latency = 0
            if self.metrics['block_latency_ms']:
                avg_block_latency = sum(self.metrics['block_latency_ms']) / len(self.metrics['block_latency_ms'])
            
            return {
                'counters': {
                    'packets_total': self.metrics['packets_total'],
                    'packets_tcp': self.metrics['packets_tcp'],
                    'packets_udp': self.metrics['packets_udp'],
                    'packets_icmp': self.metrics['packets_icmp'],
                    'detections_total': self.metrics['detections_total'],
                    'blocks_total': self.metrics['blocks_total'],
                    'false_positives_total': self.metrics['false_positives_total'],
                },
                'gauges': {
                    'active_blocks': self.metrics['active_blocks'],
                    'tracked_ips': self.metrics['tracked_ips'],
                    'avg_detection_latency_ms': avg_detection_latency,
                    'avg_block_latency_ms': avg_block_latency,
                },
                'detections_by_type': dict(self.metrics['detections_by_type']),
                'time_series': {
                    'packet_rates': list(self.metrics['packet_rate_history'])[-100:],  # Last 100 points
                    'detection_rates': list(self.metrics['detection_rate_history'])[-100:],
                    'block_rates': list(self.metrics['block_rate_history'])[-100:],
                },
                'timestamp': time.time()
            }
    
    def start(self):
        """Start metrics collection and HTTP server"""
        if not self.enabled:
            return
        
        # Start HTTP server for metrics endpoint
        self._start_metrics_server()
        
        logger.info("Metrics collector started")
    
    def stop(self):
        """Stop metrics collection"""
        if not self.enabled:
            return
        
        if self.http_server:
            self.http_server.shutdown()
            
        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=5)
        
        logger.info("Metrics collector stopped")
    
    def _start_metrics_server(self):
        """Start HTTP server for metrics endpoint"""
        port = self.metrics_config.get('port', 9090)
        path = self.metrics_config.get('path', '/metrics')
        
        class MetricsHandler(BaseHTTPRequestHandler):
            def __init__(self, metrics_collector):
                self.metrics_collector = metrics_collector
            
            def __call__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
            
            def do_GET(self):
                if self.path == path:
                    # Prometheus metrics
                    metrics_data = self.metrics_collector.get_prometheus_metrics()
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/plain; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(metrics_data.encode('utf-8'))
                elif self.path == '/metrics.json':
                    # JSON metrics
                    metrics_data = json.dumps(self.metrics_collector.get_json_metrics(), indent=2)
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(metrics_data.encode('utf-8'))
                else:
                    self.send_error(404)
            
            def log_message(self, format, *args):
                # Suppress HTTP server logs
                pass
        
        try:
            handler = MetricsHandler(self)
            self.http_server = HTTPServer(('0.0.0.0', port), handler)
            
            def server_worker():
                logger.info(f"Metrics server starting on port {port}")
                self.http_server.serve_forever()
            
            self.server_thread = threading.Thread(target=server_worker, daemon=True)
            self.server_thread.start()
            
            logger.info(f"Metrics available at http://localhost:{port}{path}")
            
        except Exception as e:
            logger.error(f"Failed to start metrics server: {e}")

if __name__ == "__main__":
    # Test metrics collector
    import yaml
    
    config = {
        'metrics': {
            'enabled': True,
            'port': 9090,
            'path': '/metrics'
        }
    }
    
    collector = MetricsCollector(config)
    collector.start()
    
    # Simulate some metrics
    from packet_capture import PacketInfo
    from detection_modules import DetectionResult
    from decision_engine import BlockAction
    
    # Test packet recording
    packet_info = PacketInfo(
        timestamp=time.time(),
        src_ip="192.168.1.100",
        dst_ip="192.168.1.1",
        protocol="TCP"
    )
    collector.record_packet(packet_info)
    
    # Test detection recording
    detection = DetectionResult(
        threat_type="SYN_FLOOD",
        score=85,
        confidence=0.9,
        details="Test detection",
        source_ip="192.168.1.100"
    )
    
    block = BlockAction("192.168.1.100", "Test block", 85, 3600)
    collector.record_detection(detection, block)
    
    # Print metrics
    print("Prometheus metrics:")
    print(collector.get_prometheus_metrics())
    
    print("\nJSON metrics:")
    print(json.dumps(collector.get_json_metrics(), indent=2))
    
    collector.stop()
