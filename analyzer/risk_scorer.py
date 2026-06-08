SPOOFING_TAMPERING_WEIGHT = 10
HIGH_PATH_WEIGHT = 15
MEDIUM_PATH_WEIGHT = 7


def calculate_risk(threats, paths):
    score = 0

    score += len([t for t in threats if t["category"] in ["Tampering", "Spoofing"]]) * SPOOFING_TAMPERING_WEIGHT
    score += len([p for p in paths if p["risk"] == "HIGH"]) * HIGH_PATH_WEIGHT
    score += len([p for p in paths if p["risk"] == "MEDIUM"]) * MEDIUM_PATH_WEIGHT

    if score < 20:
        level = "LOW"
    elif score < 50:
        level = "MEDIUM"
    else:
        level = "HIGH"

    return {
        "risk_score": score,
        "risk_level": level,
    }
