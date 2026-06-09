def build_attack_paths():

    paths = [
        {
            "attack_path": "User -> Login Endpoint -> Auth Bypass -> Admin Access",
            "risk": "HIGH"
        },
        {
            "attack_path": "User -> API -> Injection -> Database Leak",
            "risk": "HIGH"
        },
        {
            "attack_path": "User -> Frontend -> XSS -> Session Hijack",
            "risk": "MEDIUM"
        }
    ]

    return paths