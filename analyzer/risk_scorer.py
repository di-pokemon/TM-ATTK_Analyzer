def calculate_risk(threats, paths):

    score = 0

    score += len([t for t in threats if t["category"] in ["Tampering", "Spoofing"]]) * 10
    score += len([p for p in paths if p["risk"] == "HIGH"]) * 15
    score += len([p for p in paths if p["risk"] == "MEDIUM"]) * 7

    if score < 20:
        level = "LOW"
    elif score < 50:
        level = "MEDIUM"
    else:
        level = "HIGH"

    return {
        "risk_score": score,
        "risk_level": level
    }