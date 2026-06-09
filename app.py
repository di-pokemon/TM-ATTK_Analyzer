import json
from analyzer.stride_engine import generate_stride_threats
from analyzer.attack_graph import build_attack_paths
from analyzer.risk_scorer import calculate_risk

def run_analysis():

    with open("input/system_description.json") as f:
        system = json.load(f)

    threats = generate_stride_threats(system)
    paths = build_attack_paths()

    risk = calculate_risk(threats, paths)

    report = {
        "system": system["system"],
        "threats": threats,
        "attack_paths": paths,
        "risk": risk
    }

    with open("output/threat_report.json", "w") as f:
        json.dump(report, f, indent=4)

    print("Threat model generated successfully")


if __name__ == "__main__":
    run_analysis()