#!/usr/bin/env python3
"""
Network Security Agent - REST API Server
Provides REST API for managing and monitoring the security agent.
"""

import time
import threading
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import logging

logger = logging.getLogger(__name__)

class APIServer:
    """REST API server for the security agent"""
    
    def __init__(self, config: dict, agent):
        self.config = config
        self.api_config = config.get('api', {})
        self.enabled = self.api_config.get('enabled', True)
        self.agent = agent  # Reference to main agent
        
        if not self.enabled:
            logger.info("API server disabled")
            return
        
        self.host = self.api_config.get('host', '127.0.0.1')
        self.port = self.api_config.get('port', 8080)
        
        self.http_server = None
        self.server_thread = None
        
        logger.info("API server initialized")
    
    def start(self):
        """Start the API server"""
        if not self.enabled:
            return
        
        try:
            handler = self._create_handler()
            self.http_server = HTTPServer((self.host, self.port), handler)
            
            def server_worker():
                logger.info(f"API server starting on {self.host}:{self.port}")
                self.http_server.serve_forever()
            
            self.server_thread = threading.Thread(target=server_worker, daemon=True)
            self.server_thread.start()
            
            logger.info(f"API server available at http://{self.host}:{self.port}")
            
        except Exception as e:
            logger.error(f"Failed to start API server: {e}")
    
    def stop(self):
        """Stop the API server"""
        if not self.enabled or not self.http_server:
            return
        
        logger.info("Stopping API server")
        self.http_server.shutdown()
        
        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=5)
        
        logger.info("API server stopped")
    
    def _create_handler(self):
        """Create HTTP request handler"""
        api_server = self
        
        class APIHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.handle_request('GET')
            
            def do_POST(self):
                self.handle_request('POST')
            
            def do_DELETE(self):
                self.handle_request('DELETE')
            
            def handle_request(self, method):
                try:
                    parsed_url = urlparse(self.path)
                    path = parsed_url.path
                    query_params = parse_qs(parsed_url.query)
                    
                    # Route requests
                    if path == '/status' or path == '/':
                        self.handle_status()
                    elif path == '/api/v1/status':
                        self.handle_status()
                    elif path == '/api/v1/metrics':
                        self.handle_metrics()
                    elif path == '/api/v1/blocklist':
                        if method == 'GET':
                            self.handle_get_blocklist()
                        elif method == 'POST':
                            self.handle_post_blocklist()
                        elif method == 'DELETE':
                            self.handle_delete_blocklist(query_params)
                    elif path == '/api/v1/allowlist':
                        self.handle_allowlist()
                    elif path == '/api/v1/config':
                        if method == 'GET':
                            self.handle_get_config()
                        elif method == 'POST':
                            self.handle_post_config()
                    elif path == '/api/v1/stats':
                        self.handle_stats()
                    else:
                        self.send_error(404, f"Endpoint not found: {path}")
                        
                except Exception as e:
                    logger.error(f"API request error: {e}")
                    self.send_json_response({'error': str(e)}, 500)
            
            def handle_status(self):
                """Handle status endpoint"""
                status = api_server.agent.get_status()
                self.send_json_response(status)
            
            def handle_metrics(self):
                """Handle metrics endpoint"""
                if api_server.agent.metrics_collector:
                    metrics = api_server.agent.metrics_collector.get_json_metrics()
                    self.send_json_response(metrics)
                else:
                    self.send_json_response({'error': 'Metrics collector not available'}, 503)
            
            def handle_get_blocklist(self):
                """Handle GET /api/v1/blocklist"""
                blocked_ips = api_server.agent.get_blocked_ips()
                self.send_json_response({
                    'blocked_ips': blocked_ips,
                    'total_count': len(blocked_ips)
                })
            
            def handle_post_blocklist(self):
                """Handle POST /api/v1/blocklist"""
                try:
                    content_length = int(self.headers.get('Content-Length', 0))
                    post_data = self.rfile.read(content_length)
                    data = json.loads(post_data.decode('utf-8'))
                    
                    ip = data.get('ip')
                    reason = data.get('reason', 'API request')
                    ttl = data.get('ttl', 3600)
                    
                    if not ip:
                        self.send_json_response({'error': 'IP address is required'}, 400)
                        return
                    
                    success = api_server.agent.block_ip(ip, reason, ttl)
                    
                    if success:
                        self.send_json_response({
                            'message': f'IP {ip} blocked successfully',
                            'ip': ip,
                            'reason': reason,
                            'ttl': ttl
                        })
                    else:
                        self.send_json_response({'error': f'Failed to block IP {ip}'}, 500)
                        
                except json.JSONDecodeError:
                    self.send_json_response({'error': 'Invalid JSON in request body'}, 400)
                except Exception as e:
                    self.send_json_response({'error': str(e)}, 500)
            
            def handle_delete_blocklist(self, query_params):
                """Handle DELETE /api/v1/blocklist"""
                ip = query_params.get('ip', [None])[0]
                
                if not ip:
                    self.send_json_response({'error': 'IP parameter is required'}, 400)
                    return
                
                success = api_server.agent.unblock_ip(ip, 'API request')
                
                if success:
                    self.send_json_response({
                        'message': f'IP {ip} unblocked successfully',
                        'ip': ip
                    })
                else:
                    self.send_json_response({'error': f'Failed to unblock IP {ip}'}, 500)
            
            def handle_allowlist(self):
                """Handle allowlist endpoint"""
                # Get allowlist from decision engine
                if api_server.agent.decision_engine:
                    allowlist = [str(network) for network in api_server.agent.decision_engine.allowlist]
                    self.send_json_response({
                        'allowlist': allowlist,
                        'total_count': len(allowlist)
                    })
                else:
                    self.send_json_response({'error': 'Decision engine not available'}, 503)
            
            def handle_get_config(self):
                """Handle GET /api/v1/config"""
                # Return sanitized config (remove sensitive data)
                config = api_server.agent.config.copy()
                
                # Remove sensitive information
                if 'threat_intel' in config.get('access_control', {}):
                    config['access_control']['threat_intel'] = {'enabled': False, 'note': 'Hidden for security'}
                
                self.send_json_response(config)
            
            def handle_post_config(self):
                """Handle POST /api/v1/config (reload)"""
                try:
                    api_server.agent.reload_config()
                    self.send_json_response({'message': 'Configuration reloaded successfully'})
                except Exception as e:
                    self.send_json_response({'error': f'Failed to reload config: {e}'}, 500)
            
            def handle_stats(self):
                """Handle stats endpoint"""
                stats = api_server.agent.get_status()
                
                # Add additional statistics
                if api_server.agent.decision_engine:
                    decision_stats = api_server.agent.decision_engine.get_stats()
                    stats['decision_engine'] = decision_stats
                
                if api_server.agent.detection_engine:
                    detection_stats = api_server.agent.detection_engine.get_module_stats()
                    stats['detection_modules'] = detection_stats
                
                self.send_json_response(stats)
            
            def send_json_response(self, data, status_code=200):
                """Send JSON response"""
                response_data = json.dumps(data, indent=2)
                
                self.send_response(status_code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')  # CORS
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                self.end_headers()
                
                self.wfile.write(response_data.encode('utf-8'))
            
            def do_OPTIONS(self):
                """Handle CORS preflight requests"""
                self.send_response(200)
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                self.end_headers()
            
            def log_message(self, format, *args):
                """Override to use our logger"""
                logger.debug(f"API: {format % args}")
        
        return APIHandler

def create_api_documentation():
    """Generate API documentation"""
    return {
        "title": "Network Security Agent API",
        "version": "1.0.0",
        "description": "REST API for managing and monitoring the Network Security Agent",
        "endpoints": {
            "GET /": {
                "description": "Get agent status",
                "response": "Agent status information"
            },
            "GET /status": {
                "description": "Get agent status (alias for /)",
                "response": "Agent status information"
            },
            "GET /api/v1/status": {
                "description": "Get detailed agent status",
                "response": {
                    "running": "boolean",
                    "uptime_seconds": "number",
                    "uptime_human": "string",
                    "stats": "object",
                    "components": "object"
                }
            },
            "GET /api/v1/metrics": {
                "description": "Get metrics in JSON format",
                "response": "Metrics data"
            },
            "GET /api/v1/blocklist": {
                "description": "Get list of blocked IPs",
                "response": {
                    "blocked_ips": "object",
                    "total_count": "number"
                }
            },
            "POST /api/v1/blocklist": {
                "description": "Block an IP address",
                "request_body": {
                    "ip": "string (required)",
                    "reason": "string (optional)",
                    "ttl": "number (optional, default 3600)"
                },
                "response": {
                    "message": "string",
                    "ip": "string",
                    "reason": "string",
                    "ttl": "number"
                }
            },
            "DELETE /api/v1/blocklist?ip=<ip>": {
                "description": "Unblock an IP address",
                "parameters": {
                    "ip": "string (required)"
                },
                "response": {
                    "message": "string",
                    "ip": "string"
                }
            },
            "GET /api/v1/allowlist": {
                "description": "Get allowlist configuration",
                "response": {
                    "allowlist": "array",
                    "total_count": "number"
                }
            },
            "GET /api/v1/config": {
                "description": "Get agent configuration",
                "response": "Configuration object (sanitized)"
            },
            "POST /api/v1/config": {
                "description": "Reload configuration from file",
                "response": {
                    "message": "string"
                }
            },
            "GET /api/v1/stats": {
                "description": "Get comprehensive statistics",
                "response": "Detailed statistics including all components"
            }
        },
        "examples": {
            "block_ip": {
                "url": "POST /api/v1/blocklist",
                "body": {
                    "ip": "192.168.1.100",
                    "reason": "Manual block via API",
                    "ttl": 7200
                }
            },
            "unblock_ip": {
                "url": "DELETE /api/v1/blocklist?ip=192.168.1.100"
            }
        }
    }

if __name__ == "__main__":
    # Test API server
    import yaml
    from unittest.mock import Mock
    
    # Mock agent for testing
    class MockAgent:
        def __init__(self):
            self.config = {
                'api': {'enabled': True, 'host': '127.0.0.1', 'port': 8080}
            }
            self.metrics_collector = None
            self.decision_engine = None
            self.detection_engine = None
        
        def get_status(self):
            return {
                'running': True,
                'uptime_seconds': 123,
                'uptime_human': '2m 3s',
                'stats': {'packets_processed': 1000}
            }
        
        def get_blocked_ips(self):
            return {'192.168.1.100': {'reason': 'test', 'ttl': 3600}}
        
        def block_ip(self, ip, reason, ttl=3600):
            return True
        
        def unblock_ip(self, ip, reason):
            return True
        
        def reload_config(self):
            pass
    
    agent = MockAgent()
    api_server = APIServer(agent.config, agent)
    
    print("API Documentation:")
    print(json.dumps(create_api_documentation(), indent=2))
    
    api_server.start()
    print(f"Test API server running on http://127.0.0.1:8080")
    print("Try: curl http://127.0.0.1:8080/status")
    
    try:
        time.sleep(60)  # Run for 1 minute
    except KeyboardInterrupt:
        pass
    
    api_server.stop()
