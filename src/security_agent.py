#!/usr/bin/env python3
"""
Network Security Agent - Main Application
Real-time network security monitoring and automated threat response.
"""

import os
import sys
import time
import signal
import threading
import argparse
import logging
from pathlib import Path
import yaml
import json
from datetime import datetime

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from packet_capture import PacketCaptureEngine, PacketInfo
from detection_modules import DetectionEngine, DetectionResult
from decision_engine import DecisionEngine
from metrics_collector import MetricsCollector
from api_server import APIServer

logger = logging.getLogger(__name__)

class NetworkSecurityAgent:
    """Main network security agent application"""
    
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config = self._load_config()
        self.running = False
        
        # Initialize components
        self.packet_engine = None
        self.detection_engine = None
        self.decision_engine = None
        self.metrics_collector = None
        self.api_server = None
        
        # Threading
        self.capture_thread = None
        self.main_lock = threading.Lock()
        
        # Statistics
        self.start_time = time.time()
        self.stats = {
            'packets_processed': 0,
            'detections_made': 0,
            'blocks_applied': 0,
            'uptime_seconds': 0
        }
        
        # Setup logging
        self._setup_logging()
        
        logger.info("Network Security Agent initializing...")
    
    def _load_config(self) -> dict:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Configuration loaded from {self.config_path}")
            return config
        except Exception as e:
            print(f"FATAL: Failed to load config from {self.config_path}: {e}")
            sys.exit(1)
    
    def _setup_logging(self):
        """Setup logging configuration"""
        log_config = self.config.get('logging', {})
        log_level = getattr(logging, self.config['performance']['log_level'], logging.INFO)
        
        # Create log directory if it doesn't exist
        log_file = log_config.get('file', '/tmp/security-agent.log')
        log_dir = os.path.dirname(log_file)
        os.makedirs(log_dir, exist_ok=True)
        
        # Configure logging
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        if log_config.get('format') == 'json':
            log_format = '{"timestamp":"%(asctime)s","name":"%(name)s","level":"%(levelname)s","message":"%(message)s"}'
        
        logging.basicConfig(
            level=log_level,
            format=log_format,
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        logger.info(f"Logging configured: level={log_level}, file={log_file}")
    
    def _initialize_components(self):
        """Initialize all agent components"""
        try:
            # Initialize packet capture engine
            logger.info("Initializing packet capture engine...")
            self.packet_engine = PacketCaptureEngine(self.config_path)
            
            # Initialize detection engine
            logger.info("Initializing detection engine...")
            self.detection_engine = DetectionEngine(self.config)
            
            # Initialize decision engine
            logger.info("Initializing decision engine...")
            self.decision_engine = DecisionEngine(self.config)
            
            # Initialize metrics collector
            if self.config.get('metrics', {}).get('enabled', True):
                logger.info("Initializing metrics collector...")
                self.metrics_collector = MetricsCollector(self.config)
            
            # Initialize API server
            if self.config.get('api', {}).get('enabled', True):
                logger.info("Initializing API server...")
                self.api_server = APIServer(self.config, self)
            
            # Wire up callbacks
            self._setup_callbacks()
            
            logger.info("All components initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize components: {e}")
            raise
    
    def _setup_callbacks(self):
        """Setup callbacks between components"""
        # Detection results callback
        def detection_callback(detection_result: DetectionResult):
            self.stats['detections_made'] += 1
            
            # Process through decision engine
            block_action = self.decision_engine.process_detection(detection_result)
            if block_action:
                self.stats['blocks_applied'] += 1
            
            # Update metrics
            if self.metrics_collector:
                self.metrics_collector.record_detection(detection_result, block_action)
        
        self.detection_engine.add_result_callback(detection_callback)
        
        # Packet processing callback for detection engine
        def packet_callback(packet_info: PacketInfo, ip_stats):
            self.stats['packets_processed'] += 1
            
            # Run detection
            results = self.detection_engine.analyze_packet(packet_info, ip_stats)
            
            # Update metrics
            if self.metrics_collector:
                self.metrics_collector.record_packet(packet_info)
        
        # Add detection modules to packet engine
        self.packet_engine.detection_modules = [self.detection_engine]
        
        # Override packet handler to include our callback
        original_handler = self.packet_engine.packet_handler
        def enhanced_handler(packet):
            try:
                packet_info = self.packet_engine.parse_packet(packet)
                if packet_info:
                    self.packet_engine.update_ip_stats(packet_info)
                    ip_stats = self.packet_engine.get_ip_stats(packet_info.src_ip)
                    packet_callback(packet_info, ip_stats)
            except Exception as e:
                logger.error(f"Error in enhanced packet handler: {e}")
        
        self.packet_engine.packet_handler = enhanced_handler
    
    def start(self):
        """Start the security agent"""
        if self.running:
            logger.warning("Agent is already running")
            return
        
        logger.info("Starting Network Security Agent...")
        
        try:
            # Initialize all components
            self._initialize_components()
            
            # Start background services
            self._start_background_services()
            
            # Start packet capture in separate thread
            self.capture_thread = threading.Thread(
                target=self._capture_worker,
                daemon=True
            )
            self.capture_thread.start()
            
            # Mark as running
            self.running = True
            
            logger.info("🚀 Network Security Agent started successfully!")
            logger.info(f"Monitoring interface: {self.packet_engine.interface}")
            logger.info(f"Detection modules: {len(self.detection_engine.detection_modules)}")
            
            if self.api_server:
                host = self.config['api']['host']
                port = self.config['api']['port']
                logger.info(f"API server available at http://{host}:{port}")
            
            if self.metrics_collector:
                metrics_port = self.config['metrics']['port']
                logger.info(f"Metrics available at http://localhost:{metrics_port}/metrics")
            
        except Exception as e:
            logger.error(f"Failed to start agent: {e}")
            self.stop()
            raise
    
    def _start_background_services(self):
        """Start background services"""
        # Start cleanup thread for packet engine
        self.packet_engine.start_cleanup_thread()
        
        # Start metrics collector
        if self.metrics_collector:
            self.metrics_collector.start()
        
        # Start API server
        if self.api_server:
            self.api_server.start()
    
    def _capture_worker(self):
        """Worker thread for packet capture"""
        try:
            logger.info("Starting packet capture worker")
            self.packet_engine.start_capture()
        except Exception as e:
            logger.error(f"Packet capture worker error: {e}")
            self.running = False
    
    def stop(self):
        """Stop the security agent"""
        if not self.running:
            return
        
        logger.info("Stopping Network Security Agent...")
        
        # Mark as not running
        self.running = False
        
        # Stop packet capture
        if self.packet_engine:
            self.packet_engine.stop_capture()
        
        # Stop API server
        if self.api_server:
            self.api_server.stop()
        
        # Stop metrics collector
        if self.metrics_collector:
            self.metrics_collector.stop()
        
        # Shutdown decision engine
        if self.decision_engine:
            self.decision_engine.shutdown()
        
        # Wait for capture thread
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5)
        
        logger.info("Network Security Agent stopped")
    
    def reload_config(self):
        """Reload configuration from file"""
        try:
            logger.info("Reloading configuration...")
            new_config = self._load_config()
            
            # Update configuration
            old_config = self.config
            self.config = new_config
            
            # Notify components of config change
            # In a full implementation, components would support hot reload
            logger.info("Configuration reloaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to reload configuration: {e}")
            # Restore old config on failure
            self.config = old_config
    
    def get_status(self) -> dict:
        """Get agent status information"""
        current_time = time.time()
        uptime = current_time - self.start_time
        
        status = {
            'running': self.running,
            'uptime_seconds': int(uptime),
            'uptime_human': self._format_uptime(uptime),
            'start_time': datetime.fromtimestamp(self.start_time).isoformat(),
            'current_time': datetime.fromtimestamp(current_time).isoformat(),
            'stats': self.stats.copy(),
            'components': {
                'packet_engine': self.packet_engine is not None,
                'detection_engine': self.detection_engine is not None,
                'decision_engine': self.decision_engine is not None,
                'metrics_collector': self.metrics_collector is not None,
                'api_server': self.api_server is not None,
            }
        }
        
        # Add component-specific stats
        if self.decision_engine:
            status['decision_stats'] = self.decision_engine.get_stats()
        
        if self.packet_engine:
            with self.packet_engine.stats_lock:
                status['tracked_ips'] = len(self.packet_engine.ip_stats)
        
        return status
    
    def _format_uptime(self, seconds: float) -> str:
        """Format uptime in human readable format"""
        seconds = int(seconds)
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        minutes = (seconds % 3600) // 60
        seconds = seconds % 60
        
        if days > 0:
            return f"{days}d {hours}h {minutes}m {seconds}s"
        elif hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"
    
    def get_blocked_ips(self) -> dict:
        """Get currently blocked IPs"""
        if self.decision_engine:
            blocks = self.decision_engine.get_blocked_ips()
            return {ip: block.to_dict() for ip, block in blocks.items()}
        return {}
    
    def block_ip(self, ip: str, reason: str = "manual", ttl: int = 3600) -> bool:
        """Manually block an IP"""
        if self.decision_engine:
            from detection_modules import DetectionResult
            
            # Create a manual detection result
            detection = DetectionResult(
                threat_type="MANUAL_BLOCK",
                score=100,
                confidence=1.0,
                details=f"Manual block: {reason}",
                source_ip=ip
            )
            
            block = self.decision_engine.process_detection(detection)
            return block is not None
        return False
    
    def unblock_ip(self, ip: str, reason: str = "manual") -> bool:
        """Manually unblock an IP"""
        if self.decision_engine:
            return self.decision_engine.unblock_ip(ip, reason)
        return False

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info(f"Received signal {signum}, shutting down...")
    if hasattr(signal_handler, 'agent'):
        signal_handler.agent.stop()
    sys.exit(0)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Network Security Agent')
    parser.add_argument(
        '--config', '-c',
        default='/workspaces/codespaces-blank/network-security-agent/config/security_agent.yaml',
        help='Configuration file path'
    )
    parser.add_argument(
        '--daemon', '-d',
        action='store_true',
        help='Run as daemon'
    )
    parser.add_argument(
        '--test',
        action='store_true',
        help='Run in test mode with mock firewall'
    )
    parser.add_argument(
        '--pcap',
        help='Read from pcap file instead of live capture'
    )
    
    args = parser.parse_args()
    
    # Check if config file exists
    if not os.path.exists(args.config):
        print(f"FATAL: Configuration file not found: {args.config}")
        sys.exit(1)
    
    # Override config for test mode
    if args.test:
        import tempfile
        with open(args.config, 'r') as f:
            config = yaml.safe_load(f)
        
        # Set mock mode
        config['blocking']['firewall']['backend'] = 'mock'
        config['development']['mock_mode'] = True
        
        # Write temporary config
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(config, f)
            args.config = f.name
        
        print("Running in TEST MODE with mock firewall")
    
    # Override pcap file
    if args.pcap:
        with open(args.config, 'r') as f:
            config = yaml.safe_load(f)
        
        config['development']['pcap_file'] = args.pcap
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(config, f)
            args.config = f.name
        
        print(f"Reading from pcap file: {args.pcap}")
    
    try:
        # Initialize agent
        agent = NetworkSecurityAgent(args.config)
        
        # Setup signal handlers
        signal_handler.agent = agent
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Start agent
        agent.start()
        
        if args.daemon:
            # Daemon mode - just wait
            while agent.running:
                time.sleep(1)
        else:
            # Interactive mode
            print("\n🛡️  Network Security Agent is running!")
            print("Press Ctrl+C to stop, or 'h' for help")
            
            while agent.running:
                try:
                    user_input = input("> ").strip().lower()
                    
                    if user_input in ['q', 'quit', 'exit']:
                        break
                    elif user_input in ['h', 'help']:
                        print("Commands:")
                        print("  status - Show agent status")
                        print("  blocks - Show blocked IPs")
                        print("  block <ip> - Block an IP")
                        print("  unblock <ip> - Unblock an IP")
                        print("  reload - Reload configuration")
                        print("  quit - Stop agent")
                    elif user_input == 'status':
                        status = agent.get_status()
                        print(json.dumps(status, indent=2))
                    elif user_input == 'blocks':
                        blocks = agent.get_blocked_ips()
                        if blocks:
                            for ip, info in blocks.items():
                                print(f"{ip}: {info['reason']} (expires in {info['time_remaining']}s)")
                        else:
                            print("No blocked IPs")
                    elif user_input.startswith('block '):
                        ip = user_input.split()[1]
                        if agent.block_ip(ip, "manual command"):
                            print(f"Blocked {ip}")
                        else:
                            print(f"Failed to block {ip}")
                    elif user_input.startswith('unblock '):
                        ip = user_input.split()[1]
                        if agent.unblock_ip(ip, "manual command"):
                            print(f"Unblocked {ip}")
                        else:
                            print(f"Failed to unblock {ip}")
                    elif user_input == 'reload':
                        agent.reload_config()
                        print("Configuration reloaded")
                    elif user_input == '':
                        continue  # Empty input
                    else:
                        print(f"Unknown command: {user_input}")
                        
                except EOFError:
                    break
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"Error: {e}")
        
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)
    finally:
        # Cleanup
        if 'agent' in locals():
            agent.stop()
        
        # Remove temporary config files
        if args.test or args.pcap:
            try:
                os.unlink(args.config)
            except:
                pass

if __name__ == "__main__":
    main()
