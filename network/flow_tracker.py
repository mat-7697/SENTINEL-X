import json
from datetime import datetime


def get_flow_key(event):
    """
    Creates a bidirectional flow key.

    Packets traveling A -> B and B -> A
    should belong to the same flow.
    """

    endpoint1 = (
        event["source_ip"],
        event["source_port"]
    )

    endpoint2 = (
        event["destination_ip"],
        event["destination_port"]
    )

    if endpoint1 <= endpoint2:
        return (
            endpoint1,
            endpoint2,
            event["protocol"]
        )

    return (
        endpoint2,
        endpoint1,
        event["protocol"]
    )


def get_direction(event, flow_key):
    """
    Determines whether the packet belongs to
    the forward or reverse direction.
    """

    source_endpoint = (
        event["source_ip"],
        event["source_port"]
    )

    if source_endpoint == flow_key[0]:
        return "forward"

    return "reverse"

def update_tcp_flags(flow, event):
    """
    Updates TCP flag counters for a flow.
    """

    if event["protocol"] != "TCP":
        return

    flags = event.get("flags", "")

    if "S" in flags and "A" in flags:
        flow["syn_ack_count"] += 1

    elif "S" in flags:
        flow["syn_count"] += 1

    if "A" in flags:
        flow["ack_count"] += 1

    if "F" in flags:
        flow["fin_count"] += 1

    if "R" in flags:
        flow["rst_count"] += 1

    if "P" in flags:
        flow["psh_count"] += 1

def create_flow(event):
    """
    Creates a new flow from the first packet.
    """

    flow = {
        "source_ip": event["source_ip"],
        "destination_ip": event["destination_ip"],
        "source_port": event["source_port"],
        "destination_port": event["destination_port"],
        "protocol": event["protocol"],

        "start_time": event["timestamp"],
        "end_time": event["timestamp"],

        "packet_count": 1,
        "total_bytes": event["size"],

        "forward_packets": 1,
        "reverse_packets": 0,

        "forward_bytes": event["size"],
        "reverse_bytes": 0,

        "syn_count": 0,
        "syn_ack_count": 0,
        "ack_count": 0,
        "fin_count": 0,
        "rst_count": 0,
        "psh_count": 0
    }

    update_tcp_flags(flow, event)

    return flow


def update_flow(flow, event, direction):

    flow["end_time"] = event["timestamp"]

    flow["packet_count"] += 1
    flow["total_bytes"] += event["size"]

    if direction == "forward":
        flow["forward_packets"] += 1
        flow["forward_bytes"] += event["size"]

    else:
        flow["reverse_packets"] += 1
        flow["reverse_bytes"] += event["size"]

    update_tcp_flags(flow, event)


def load_events(filename):
    """
    Reads network events from a JSONL file.
    """

    events = []

    with open(filename, "r") as file:

        for line in file:

            if line.strip():
                event = json.loads(line)
                events.append(event)

    return events


def build_flows(events):
    """
    Groups packets into bidirectional flows.
    """

    flows = {}

    for event in events:

        flow_key = get_flow_key(event)

        if flow_key not in flows:

            flows[flow_key] = create_flow(event)

        else:

            direction = get_direction(
                event,
                flow_key
            )

            update_flow(
                flows[flow_key],
                event,
                direction
            )

    # Calculate derived features after
    # all packets have been processed.
    for flow in flows.values():
        calculate_flow_features(flow)

    return flows


def calculate_flow_features(flow):
    """
    Calculates derived flow-level features.
    """

    start = datetime.fromisoformat(
        flow["start_time"]
    )

    end = datetime.fromisoformat(
        flow["end_time"]
    )

    duration = (end - start).total_seconds()

    flow["duration"] = duration

    if duration > 0:

        flow["packets_per_second"] = (
            flow["packet_count"] / duration
        )

        flow["bytes_per_second"] = (
            flow["total_bytes"] / duration
        )

    else:

        flow["packets_per_second"] = 0
        flow["bytes_per_second"] = 0

    return flow

def save_flows(flows, filename):
    """
    Saves each flow as one JSON object per line.
    """

    with open(filename, "w") as file:

        for flow in flows.values():
            file.write(json.dumps(flow) + "\n")

def main():

    filename = "logs/network_events.jsonl"

    events = load_events(filename)

    flows = build_flows(events)

    save_flows(
        flows,
        "logs/flows.jsonl"
    )

    print(f"Total network events: {len(events)}")
    print(f"Total flows: {len(flows)}")

    print("\n--- FLOWS ---")

    for flow_key, flow in flows.items():

        print("\nFlow:")
        print(flow)


if __name__ == "__main__":
    main()