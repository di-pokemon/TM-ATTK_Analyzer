def build_attack_paths(system):
    has_database = any("database" in component.lower() for component in system.get("components", []))

    paths = [
        {
            "attack_path": "User -> Login Endpoint -> Auth Bypass -> Admin Access",
            "risk": "HIGH",
        },
        {
            "attack_path": "User -> Frontend -> XSS -> Session Hijack",
            "risk": "MEDIUM",
        },
    ]

    if has_database:
        paths.insert(
            1,
            {
                "attack_path": "User -> API -> Injection -> Database Leak",
                "risk": "HIGH",
            },
        )

    return paths
