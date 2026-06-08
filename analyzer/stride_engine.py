def generate_stride_threats(system):
    threats = [
        {"category": "Spoofing", "description": "Weak authentication may allow impersonation"},
        {"category": "Tampering", "description": "API requests may be modified in transit"},
        {"category": "Repudiation", "description": "Lack of logging prevents traceability"},
        {"category": "Information Disclosure", "description": "Sensitive data may be exposed via API"},
        {"category": "Denial of Service", "description": "No rate limiting allows abuse"},
        {"category": "Elevation of Privilege", "description": "Broken access control may expose admin functions"},
    ]

    return threats
