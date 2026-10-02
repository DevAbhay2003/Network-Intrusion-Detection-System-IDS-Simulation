"""
Input Validation and Sanitization Utilities
Defensive Cybersecurity Engineering Project: Network Intrusion Detection System (IDS) Simulation
"""

import html
import ipaddress
import re
from typing import Tuple, Optional


def validate_network_endpoint(ip: str, port: int) -> Tuple[bool, Optional[str]]:
    """
    Validates IP address format and port range.
    """
    if not ip or not isinstance(ip, str):
        return False, "IP address cannot be empty"

    try:
        ipaddress.ip_address(ip.strip())
    except ValueError:
        return False, f"Invalid IP address format: {ip}"

    if not isinstance(port, int) or port < 1 or port > 65535:
        return False, f"Port must be an integer between 1 and 65535 (received: {port})"

    return True, None


def sanitize_text(text: str) -> str:
    """
    Sanitizes user input (such as analyst notes) to prevent XSS / script injection.
    """
    if not text:
        return ""
    # Strip dangerous HTML and escape entities
    escaped = html.escape(text.strip())
    return escaped
