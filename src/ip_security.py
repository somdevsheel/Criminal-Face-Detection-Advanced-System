"""
IP-Based Access Control
Whitelist authorized IP addresses for high-security access
"""

import logging
from functools import wraps
from flask import request, jsonify
import ipaddress
from typing import List, Set

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IPWhitelist:
    """
    Manage IP whitelist for secure access control
    """
    
    def __init__(self, whitelist_file: str = "config/ip_whitelist.txt"):
        """
        Initialize IP whitelist
        
        Args:
            whitelist_file: Path to file containing allowed IPs
        """
        self.whitelist_file = whitelist_file
        self.allowed_ips: Set[str] = set()
        self.allowed_networks: List[ipaddress.IPv4Network] = []
        self.load_whitelist()
    
    def load_whitelist(self):
        """Load IP whitelist from file"""
        try:
            with open(self.whitelist_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Check if it's a network (CIDR notation)
                        if '/' in line:
                            try:
                                network = ipaddress.IPv4Network(line, strict=False)
                                self.allowed_networks.append(network)
                                logger.info(f"Added network to whitelist: {line}")
                            except ValueError:
                                logger.warning(f"Invalid network format: {line}")
                        else:
                            # Single IP address
                            self.allowed_ips.add(line)
                            logger.info(f"Added IP to whitelist: {line}")
            
            logger.info(f"Loaded {len(self.allowed_ips)} IPs and {len(self.allowed_networks)} networks")
        
        except FileNotFoundError:
            logger.warning(f"Whitelist file not found: {self.whitelist_file}")
            # Create default whitelist
            self._create_default_whitelist()
    
    def _create_default_whitelist(self):
        """Create default whitelist with localhost"""
        import os
        os.makedirs(os.path.dirname(self.whitelist_file), exist_ok=True)
        
        with open(self.whitelist_file, 'w') as f:
            f.write("# IP Whitelist - High Security Criminal Detection System\n")
            f.write("# Add authorized IP addresses or networks (CIDR notation)\n")
            f.write("# One per line, lines starting with # are comments\n\n")
            f.write("# Localhost\n")
            f.write("127.0.0.1\n")
            f.write("::1\n")
            f.write("localhost\n\n")
            f.write("# Local network (example - adjust as needed)\n")
            f.write("# 192.168.1.0/24\n\n")
            f.write("# Add your authorized IPs below:\n")
        
        logger.info("Created default whitelist file")
        self.allowed_ips = {'127.0.0.1', '::1', 'localhost'}
    
    def is_allowed(self, ip_address: str) -> bool:
        """
        Check if IP address is whitelisted
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if allowed, False otherwise
        """
        # Allow localhost variations
        if ip_address in ['127.0.0.1', '::1', 'localhost']:
            return True
        
        # Check exact match
        if ip_address in self.allowed_ips:
            return True
        
        # Check network ranges
        try:
            ip = ipaddress.IPv4Address(ip_address)
            for network in self.allowed_networks:
                if ip in network:
                    return True
        except ValueError:
            logger.warning(f"Invalid IP address format: {ip_address}")
        
        return False
    
    def add_ip(self, ip_address: str):
        """Add IP to whitelist"""
        self.allowed_ips.add(ip_address)
        self._save_whitelist()
        logger.info(f"Added IP to whitelist: {ip_address}")
    
    def remove_ip(self, ip_address: str):
        """Remove IP from whitelist"""
        self.allowed_ips.discard(ip_address)
        self._save_whitelist()
        logger.info(f"Removed IP from whitelist: {ip_address}")
    
    def _save_whitelist(self):
        """Save whitelist to file"""
        with open(self.whitelist_file, 'w') as f:
            f.write("# IP Whitelist - Auto-updated\n\n")
            for ip in sorted(self.allowed_ips):
                f.write(f"{ip}\n")
            for network in self.allowed_networks:
                f.write(f"{network}\n")


# Flask decorator for IP whitelist protection
def require_whitelisted_ip(whitelist: IPWhitelist):
    """
    Decorator to protect routes with IP whitelist
    
    Usage:
        @app.route('/secure-endpoint')
        @require_whitelisted_ip(ip_whitelist)
        def secure_function():
            return "Authorized"
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get client IP
            if request.headers.getlist("X-Forwarded-For"):
                client_ip = request.headers.getlist("X-Forwarded-For")[0]
            else:
                client_ip = request.remote_addr
            
            logger.info(f"Access attempt from IP: {client_ip}")
            
            # Check whitelist
            if not whitelist.is_allowed(client_ip):
                logger.warning(f"Unauthorized access attempt from: {client_ip}")
                return jsonify({
                    'success': False,
                    'error': 'Access denied: IP address not authorized',
                    'ip': client_ip
                }), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


# Example usage
if __name__ == "__main__":
    whitelist = IPWhitelist()
    
    # Test IPs
    test_ips = [
        '127.0.0.1',
        '192.168.1.100',
        '10.0.0.1',
        '8.8.8.8'
    ]
    
    for ip in test_ips:
        allowed = whitelist.is_allowed(ip)
        print(f"{ip}: {'✓ ALLOWED' if allowed else '✗ DENIED'}")