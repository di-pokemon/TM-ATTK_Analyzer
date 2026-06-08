import json
from pathlib import Path

from analyzer.attack_graph import build_attack_paths
from analyzer.risk_scorer import calculate_risk
from analyzer.stride_engine import generate_stride_threats


def run_analysis():
    base_dir = Path(__file__).resolve().parent
    input_path = base_dir / "input" / "system_description.json"
    output_path = base_dir / "output" / "threat_report.json"

    with input_path.open() as f:
        system = json.load(f)

    threats = generate_stride_threats(system)
    paths = build_attack_paths(system)
    risk = calculate_risk(threats, paths)

    report = {
        "system": system["system"],
        "threats": threats,
        "attack_paths": paths,
        "risk": risk,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w") as f:
        json.dump(report, f, indent=4)

    print("Threat model generated successfully")


if __name__ == "__main__":
    run_analysis()
