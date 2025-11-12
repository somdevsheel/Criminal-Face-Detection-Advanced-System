"""
Multi-Factor Authentication System
Implements TOTP (Time-based One-Time Password) for 2FA
"""

import pyotp
import qrcode
import io
import base64
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MFASystem:
    """
    Two-Factor Authentication using TOTP
    """
    
    def __init__(self):
        """Initialize MFA system"""
        self.issuer_name = "Criminal Detection System"
    
    def generate_secret(self) -> str:
        """
        Generate a new secret key for a user
        
        Returns:
            Base32-encoded secret key
        """
        return pyotp.random_base32()
    
    def get_provisioning_uri(self, username: str, secret: str) -> str:
        """
        Get provisioning URI for QR code
        
        Args:
            username: User's username
            secret: User's secret key
            
        Returns:
            Provisioning URI
        """
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(
            name=username,
            issuer_name=self.issuer_name
        )
    
    def generate_qr_code(self, username: str, secret: str) -> str:
        """
        Generate QR code for authenticator app
        
        Args:
            username: User's username
            secret: User's secret key
            
        Returns:
            Base64-encoded QR code image
        """
        uri = self.get_provisioning_uri(username, secret)
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        img_base64 = base64.b64encode(buffer.getvalue()).decode()
        
        return f"data:image/png;base64,{img_base64}"
    
    def verify_token(self, secret: str, token: str) -> bool:
        """
        Verify a TOTP token
        
        Args:
            secret: User's secret key
            token: 6-digit token from authenticator app
            
        Returns:
            True if token is valid, False otherwise
        """
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(token, valid_window=1)  # Allow 1 time step tolerance
        except Exception as e:
            logger.error(f"Error verifying token: {e}")
            return False
    
    def get_current_token(self, secret: str) -> str:
        """
        Get current token (for testing)
        
        Args:
            secret: User's secret key
            
        Returns:
            Current 6-digit token
        """
        totp = pyotp.TOTP(secret)
        return totp.now()


class BackupCodes:
    """
    Generate and manage backup codes for account recovery
    """
    
    @staticmethod
    def generate_codes(count: int = 10) -> list:
        """
        Generate backup codes
        
        Args:
            count: Number of codes to generate
            
        Returns:
            List of backup codes
        """
        import secrets
        codes = []
        for _ in range(count):
            code = '-'.join([
                secrets.token_hex(2).upper() for _ in range(4)
            ])
            codes.append(code)
        return codes
    
    @staticmethod
    def hash_code(code: str) -> str:
        """Hash a backup code for storage"""
        import hashlib
        return hashlib.sha256(code.encode()).hexdigest()
    
    @staticmethod
    def verify_code(code: str, hashed_code: str) -> bool:
        """Verify a backup code"""
        return BackupCodes.hash_code(code) == hashed_code


# Example usage
if __name__ == "__main__":
    mfa = MFASystem()
    
    # Setup for new user
    username = "admin"
    secret = mfa.generate_secret()
    
    print(f"Secret key: {secret}")
    print(f"Provisioning URI: {mfa.get_provisioning_uri(username, secret)}")
    print(f"\nScan this QR code with Google Authenticator or similar app")
    
    # Generate QR code
    qr_code = mfa.generate_qr_code(username, secret)
    print(f"QR Code (base64): {qr_code[:100]}...")
    
    # Test verification
    current_token = mfa.get_current_token(secret)
    print(f"\nCurrent token: {current_token}")
    print(f"Verification: {mfa.verify_token(secret, current_token)}")
    
    # Generate backup codes
    backup_codes = BackupCodes.generate_codes(10)
    print(f"\nBackup codes:")
    for code in backup_codes:
        print(f"  {code}")