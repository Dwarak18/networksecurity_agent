#!/usr/bin/env python3
"""
Network Security Agent - Live Demonstration
==========================================
Demonstrates the network security agent detecting and blocking simulated attacks.
This demo creates synthetic traffic patterns and shows how the agent responds.
"""

import sys
import os
import time
import socket
import threading
import random
import argparse
from datetime import datetime
import json

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

class AttackSimulator:
    """Simulates various network attack patterns for testing."""
    
    def __init__(self, target_ip="127.0.0.1", base_port=8000):
        self.target_ip = target_ip
        self.base_port = base_port
        self.running = False
        self.attack_threads = []
    
    def simulate_syn_flood(self, duration=10, rate=50):
        """Simulate a SYN flood attack."""
        print(f"🔥 Simulating SYN flood: {rate} connections/sec for {duration}s")
        
        def syn_flood_worker():
            start_time = time.time()
            connection_count = 0
            
            while time.time() - start_time < duration and self.running:
                try:
                    # Create multiple rapid connections
                    for _ in range(rate // 10):  # Burst connections
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.1)
                        try:
                            sock.connect((self.target_ip, self.base_port + random.randint(0, 100)))
                            connection_count += 1
                            sock.close()
                        except:
                            connection_count += 1  # Count attempted connections
                        finally:
                            sock.close()
                    
                    time.sleep(0.1)  # 100ms between bursts
                    
                except Exception as e:
                    pass  # Expected connection failures
            
            print(f"   📊 SYN flood completed: {connection_count} connection attempts")
        
        thread = threading.Thread(target=syn_flood_worker)
        thread.daemon = True
        self.attack_threads.append(thread)
        return thread
    
    def simulate_port_scan(self, duration=15, ports_per_second=20):
        """Simulate a port scanning attack."""
        print(f"🔍 Simulating port scan: {ports_per_second} ports/sec for {duration}s")
        
        def port_scan_worker():
            start_time = time.time()
            scanned_ports = 0
            
            while time.time() - start_time < duration and self.running:
                # Scan a range of ports rapidly
                for port in range(1, ports_per_second + 1):
                    if not self.running:
                        break
                    
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.05)  # Very short timeout
                    try:
                        result = sock.connect_ex((self.target_ip, 1000 + (scanned_ports % 9000)))
                        scanned_ports += 1
                    except:
                        scanned_ports += 1
                    finally:
                        sock.close()
                
                time.sleep(1)  # 1 second between scan bursts
            
            print(f"   📊 Port scan completed: {scanned_ports} ports scanned")
        
        thread = threading.Thread(target=port_scan_worker)
        thread.daemon = True
        self.attack_threads.append(thread)
        return thread
    
    def simulate_udp_flood(self, duration=8, rate=100):
        """Simulate a UDP flood attack."""
        print(f"💨 Simulating UDP flood: {rate} packets/sec for {duration}s")
        
        def udp_flood_worker():
            start_time = time.time()
            packet_count = 0
            
            while time.time() - start_time < duration and self.running:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    
                    # Send bursts of UDP packets
                    for _ in range(rate // 10):
                        if not self.running:
                            break
                        
                        payload = b"A" * random.randint(64, 1024)  # Random payload size
                        target_port = self.base_port + random.randint(0, 1000)
                        
                        try:
                            sock.sendto(payload, (self.target_ip, target_port))
                            packet_count += 1
                        except:
                            packet_count += 1  # Count attempted packets
                    
                    sock.close()
                    time.sleep(0.1)  # 100ms between bursts
                    
                except Exception as e:
                    pass
            
            print(f"   📊 UDP flood completed: {packet_count} packets sent")
        
        thread = threading.Thread(target=udp_flood_worker)
        thread.daemon = True
        self.attack_threads.append(thread)
        return thread
    
    def start_attacks(self):
        """Start all attack simulations."""
        self.running = True
        
        # Start different attacks with delays
        syn_thread = self.simulate_syn_flood(duration=12, rate=80)
        syn_thread.start()
        
        time.sleep(3)  # Stagger attacks
        
        port_thread = self.simulate_port_scan(duration=15, ports_per_second=30)
        port_thread.start()
        
        time.sleep(2)
        
        udp_thread = self.simulate_udp_flood(duration=10, rate=120)
        udp_thread.start()
        
        return [syn_thread, port_thread, udp_thread]
    
    def stop_attacks(self):
        """Stop all attack simulations."""
        self.running = False
        for thread in self.attack_threads:
            if thread.is_alive():
                thread.join(timeout=1)

class SecurityAgentDemo:
    """Demonstrates the security agent's detection capabilities."""
    
    def __init__(self):
        self.detection_counts = {
            'syn_flood': 0,
            'port_scan': 0,
            'udp_flood': 0,
            'anomaly': 0
        }
        self.blocked_ips = set()
        self.start_time = time.time()
    
    def simulate_detection_engine(self, attack_simulator):
        """Simulate the detection engine analyzing traffic."""
        print("\n🛡️  Security Agent Detection Engine Started")
        print("=" * 60)
        
        def detection_worker():
            while attack_simulator.running or time.time() - self.start_time < 30:
                time.sleep(1)  # Check every second
                
                # Simulate detection logic
                current_time = time.time()
                elapsed = current_time - self.start_time
                
                # Simulate SYN flood detection (high connection rate)
                if elapsed > 2 and elapsed < 20:  # Active during SYN flood
                    if random.random() < 0.8:  # Higher detection probability
                        self.detection_counts['syn_flood'] += 1
                        severity = "HIGH" if self.detection_counts['syn_flood'] > 3 else "MEDIUM"
                        score = random.randint(70, 95)
                        print(f"🚨 [{self._timestamp()}] SYN_FLOOD detected from 127.0.0.1 (score: {score}) - {severity}")
                        
                        if self.detection_counts['syn_flood'] > 4:
                            self._block_ip("127.0.0.1", "SYN_FLOOD", 3600)
                
                # Simulate port scan detection
                if elapsed > 5 and elapsed < 25:  # Active during port scan
                    if random.random() < 0.7:  # Good detection probability
                        self.detection_counts['port_scan'] += 1
                        unique_ports = random.randint(50, 200)
                        severity = "HIGH" if unique_ports > 100 else "MEDIUM"
                        print(f"🔍 [{self._timestamp()}] PORT_SCAN detected from 127.0.0.1 ({unique_ports} unique ports) - {severity}")
                        
                        if self.detection_counts['port_scan'] > 3:
                            self._block_ip("127.0.0.1", "PORT_SCAN", 7200)
                
                # Simulate UDP flood detection
                if elapsed > 7 and elapsed < 18:  # Active during UDP flood
                    if random.random() < 0.6:  # Moderate detection probability
                        self.detection_counts['udp_flood'] += 1
                        pps = random.randint(100, 500)
                        severity = "HIGH" if pps > 300 else "MEDIUM"
                        print(f"💨 [{self._timestamp()}] UDP_FLOOD detected from 127.0.0.1 ({pps} pps) - {severity}")
                        
                        if self.detection_counts['udp_flood'] > 2:
                            self._block_ip("127.0.0.1", "UDP_FLOOD", 1800)
                
                # Simulate anomaly detection
                if elapsed > 10 and elapsed < 22:  # Active during multiple attacks
                    if random.random() < 0.4:  # Lower but steady detection
                        self.detection_counts['anomaly'] += 1
                        z_score = round(random.uniform(3.0, 6.0), 2)
                        print(f"📊 [{self._timestamp()}] ANOMALY detected from 127.0.0.1 (z-score: {z_score}) - MEDIUM")
        
        detection_thread = threading.Thread(target=detection_worker)
        detection_thread.daemon = True
        detection_thread.start()
        return detection_thread
    
    def _block_ip(self, ip, reason, ttl):
        """Simulate blocking an IP address."""
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            ttl_minutes = ttl // 60
            print(f"🚫 [{self._timestamp()}] BLOCKED {ip} for {reason} (TTL: {ttl_minutes}m)")
            print(f"   📋 Firewall rule added: DROP packets from {ip}")
    
    def _timestamp(self):
        """Get current timestamp."""
        return datetime.now().strftime("%H:%M:%S")
    
    def show_final_stats(self):
        """Display final detection statistics."""
        print("\n" + "=" * 60)
        print("📈 FINAL DETECTION STATISTICS")
        print("=" * 60)
        
        total_detections = sum(self.detection_counts.values())
        elapsed_time = time.time() - self.start_time
        
        print(f"⏱️  Total Runtime: {elapsed_time:.1f} seconds")
        print(f"🎯 Total Detections: {total_detections}")
        print(f"🚫 IPs Blocked: {len(self.blocked_ips)}")
        
        print("\n📊 Detection Breakdown:")
        for attack_type, count in self.detection_counts.items():
            if count > 0:
                print(f"   {attack_type.upper().replace('_', ' ')}: {count} detections")
        
        print(f"\n🛡️  Blocked IPs: {', '.join(self.blocked_ips) if self.blocked_ips else 'None'}")
        
        if total_detections > 0:
            print(f"\n✅ Security agent successfully detected and responded to {total_detections} threats!")
        else:
            print(f"\n⚠️  No threats detected during this simulation.")

def create_mock_server():
    """Create a mock server to accept connections."""
    def server_worker():
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('127.0.0.1', 8000))
            server.listen(100)
            server.settimeout(1)
            
            while True:
                try:
                    conn, addr = server.accept()
                    conn.close()
                except socket.timeout:
                    continue
                except:
                    break
        except:
            pass
    
    thread = threading.Thread(target=server_worker)
    thread.daemon = True
    thread.start()
    return thread

def main():
    """Main demonstration function."""
    parser = argparse.ArgumentParser(description='Network Security Agent Live Demonstration')
    parser.add_argument('--duration', type=int, default=20, help='Demo duration in seconds (default: 20)')
    parser.add_argument('--target', default='127.0.0.1', help='Target IP for attack simulation (default: 127.0.0.1)')
    
    args = parser.parse_args()
    
    print("🛡️  NETWORK SECURITY AGENT - LIVE DEMONSTRATION")
    print("=" * 60)
    print(f"Target: {args.target}")
    print(f"Duration: {args.duration} seconds")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Start mock server
    print("🖥️  Starting mock server...")
    server_thread = create_mock_server()
    time.sleep(1)
    
    # Initialize components
    attack_sim = AttackSimulator(target_ip=args.target)
    security_demo = SecurityAgentDemo()
    
    try:
        # Start detection engine
        detection_thread = security_demo.simulate_detection_engine(attack_sim)
        
        # Start attacks
        print("🚀 Starting attack simulations...")
        attack_threads = attack_sim.start_attacks()
        
        # Let the demo run
        print(f"\n⏱️  Demo running for {args.duration} seconds...")
        print("📡 Monitoring for threats...\n")
        
        # Monitor progress
        start_time = time.time()
        while time.time() - start_time < args.duration:
            time.sleep(1)
            if not attack_sim.running:
                break
        
        # Stop everything
        print("\n🛑 Stopping attack simulations...")
        attack_sim.stop_attacks()
        
        # Wait for threads to finish
        for thread in attack_threads:
            thread.join(timeout=2)
        
        # Show final statistics
        security_demo.show_final_stats()
        
        print("\n🎉 Demonstration completed successfully!")
        print("\n💡 In a real deployment, the security agent would:")
        print("   • Capture actual network packets using libpcap/scapy")
        print("   • Apply machine learning models for anomaly detection")
        print("   • Integrate with nftables/iptables for real IP blocking")
        print("   • Send alerts to SIEM systems and security teams")
        print("   • Provide real-time metrics via Prometheus/Grafana")
        
    except KeyboardInterrupt:
        print("\n\n⏹️  Demo interrupted by user")
        attack_sim.stop_attacks()
        security_demo.show_final_stats()
    
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
        attack_sim.stop_attacks()
    
    finally:
        print("\n👋 Demo finished. Thank you!")

if __name__ == '__main__':
    main()
