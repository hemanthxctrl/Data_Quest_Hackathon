import pyshark
import time
from collections import defaultdict

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"
INTERFACE = r"\Device\NPF_{0350BCF4-067A-46D6-A32F-C1D7309AF8A3}"

FLOW_TIMEOUT = 10

flows = {}


def get_flow_key(packet):
    if not hasattr(packet, "ip"):
        return None

    src_ip = packet.ip.src
    dst_ip = packet.ip.dst

    protocol = packet.transport_layer if hasattr(packet, "transport_layer") else "OTHER"

    src_port = 0
    dst_port = 0

    if hasattr(packet, "tcp"):
        src_port = packet.tcp.srcport
        dst_port = packet.tcp.dstport

    elif hasattr(packet, "udp"):
        src_port = packet.udp.srcport
        dst_port = packet.udp.dstport

    return (
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol
    )


def process_packet(packet):
    key = get_flow_key(packet)

    if key is None:
        return

    packet_length = int(packet.length)
    current_time = time.time()

    if key not in flows:
        flows[key] = {
            "first_seen": current_time,
            "last_seen": current_time,
            "packet_count": 0,
            "total_bytes": 0
        }

    flow = flows[key]

    flow["last_seen"] = current_time
    flow["packet_count"] += 1
    flow["total_bytes"] += packet_length


def print_flows():
    print("\n========== ACTIVE FLOWS ==========")

    current_time = time.time()

    for key, flow in list(flows.items()):

        age = current_time - flow["last_seen"]

        if age > FLOW_TIMEOUT:
            src_ip, dst_ip, src_port, dst_port, protocol = key

            duration = flow["last_seen"] - flow["first_seen"]

            print(
                f"{src_ip}:{src_port} → "
                f"{dst_ip}:{dst_port} | "
                f"{protocol} | "
                f"Packets: {flow['packet_count']} | "
                f"Bytes: {flow['total_bytes']} | "
                f"Duration: {duration:.2f}s"
            )

            del flows[key]


print("===================================")
print(" LIVE NETWORK FLOW MONITOR")
print("===================================")
print("Interface: Ethernet")
print("Waiting for network flows...\n")

capture = pyshark.LiveCapture(
    interface=INTERFACE,
    tshark_path=TSHARK_PATH
)

try:
    last_print = time.time()

    for packet in capture.sniff_continuously():

        process_packet(packet)

        if time.time() - last_print >= 5:
            print_flows()
            last_print = time.time()

except KeyboardInterrupt:
    print("\nLive monitor stopped.")

finally:
    capture.close()