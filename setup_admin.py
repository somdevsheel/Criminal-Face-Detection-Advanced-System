"""
Quick setup script for admin panel
"""

import os
import sys

# Check if admin files exist
files_needed = {
    'src/admin_panel.py': 'Admin panel module',
    'src/ip_security.py': 'IP security module',
    'web/templates/admin_login.html': 'Admin login page',
    'web/templates/admin_dashboard.html': 'Admin dashboard',
    'config/ip_whitelist.txt': 'IP whitelist configuration'
}

print("Checking admin setup...")
print("=" * 60)

missing_files = []
for file, desc in files_needed.items():
    if os.path.exists(file):
        print(f"✓ {desc}: Found")
    else:
        print(f"✗ {desc}: MISSING")
        missing_files.append(file)

if missing_files:
    print("\n⚠️  Missing files:")
    for f in missing_files:
        print(f"  - {f}")
    print("\nPlease create these files from the provided code.")
else:
    print("\n✅ All admin files are in place!")
    print("\nAccess admin panel at: http://localhost:5000/admin/login")
    print("Default credentials:")
    print("  Username: admin")
    print("  Password: admin123")