import json
from datetime import datetime, timezone

from scapy.all import sniff, IP, TCP, UDP, ICMP


def parse_packet(packet):
    if IP not in packet:
        return None

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": packet[IP].src,
        "destination_ip": packet[IP].dst,
        "protocol": "IP",
        "size": len(packet),
    }

    if TCP in packet:
        event["protocol"] = "TCP"
        event["source_port"] = packet[TCP].sport
        event["destination_port"] = packet[TCP].dport
        event["flags"] = str(packet[TCP].flags)

    elif UDP in packet:
        event["protocol"] = "UDP"
        event["source_port"] = packet[UDP].sport
        event["destination_port"] = packet[UDP].dport

    elif ICMP in packet:
        event["protocol"] = "ICMP"
        event["icmp_type"] = packet[ICMP].type
        event["icmp_code"] = packet[ICMP].code

    return event


def save_event(event):
    with open("logs/network_events.jsonl", "a") as file:
        file.write(json.dumps(event) + "\n")


def process_packet(packet):
    event = parse_packet(packet)

    if event is not None:
        print(event)
        save_event(event)


sniff(count=10, prn=process_packet)