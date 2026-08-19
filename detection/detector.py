import json


# --------------------------------
# Detection thresholds
# --------------------------------

THRESHOLDS = {
    "max_packets_per_second": 1000,
    "max_bytes_per_second": 1_000_000,
    "max_rst_ratio": 0.5
}


# --------------------------------
# Load flows
# --------------------------------

def load_flows(filename):

    flows = []

    with open(filename, "r") as file:

        for line in file:

            if line.strip():

                flow = json.loads(line)
                flows.append(flow)

    return flows


# --------------------------------
# Detect anomalies
# --------------------------------

def detect_flow(flow):

    alerts = []

    # Ignore invalid flows

    if not flow.get("valid", False):

        alerts.append({
            "type": "invalid_flow",
            "severity": "HIGH",
            "reason": "Flow failed validation"
        })

        return alerts

    # -----------------------------
    # High packet rate
    # -----------------------------

    if (
        flow["packets_per_second"]
        > THRESHOLDS["max_packets_per_second"]
    ):

        alerts.append({
            "type": "high_packet_rate",
            "severity": "MEDIUM",
            "reason": (
                f"Packet rate is "
                f"{flow['packets_per_second']:.2f} "
                f"packets/sec"
            )
        })

    # -----------------------------
    # High byte rate
    # -----------------------------

    if (
        flow["bytes_per_second"]
        > THRESHOLDS["max_bytes_per_second"]
    ):

        alerts.append({
            "type": "high_byte_rate",
            "severity": "MEDIUM",
            "reason": (
                f"Byte rate is "
                f"{flow['bytes_per_second']:.2f} "
                f"bytes/sec"
            )
        })

    # -----------------------------
    # High RST ratio
    # -----------------------------

    if (
        flow["rst_ratio"]
        > THRESHOLDS["max_rst_ratio"]
    ):

        alerts.append({
            "type": "high_rst_ratio",
            "severity": "MEDIUM",
            "reason": (
                f"RST ratio is "
                f"{flow['rst_ratio']:.2f}"
            )
        })

    return alerts


# --------------------------------
# Main
# --------------------------------

def main():

    flows = load_flows(
        "logs/flows.jsonl"
    )

    print(
        f"Loaded {len(flows)} flows"
    )

    total_alerts = 0

    for flow in flows:

        alerts = detect_flow(flow)

        if alerts:

            print("\n🚨 ALERT")

            print(
                f"{flow['source_ip']}:{flow['source_port']}"
                f" -> "
                f"{flow['destination_ip']}:{flow['destination_port']}"
            )

            print(
                f"Protocol: {flow['protocol']}"
            )

            for alert in alerts:

                print(
                    f"Type: {alert['type']}"
                )

                print(
                    f"Severity: {alert['severity']}"
                )

                print(
                    f"Reason: {alert['reason']}"
                )

                total_alerts += 1

    print(
        f"\nTotal alerts: {total_alerts}"
    )


if __name__ == "__main__":
    main()