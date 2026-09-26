import time
import joblib
import pandas as pd
import pyshark

from live_flow_features import build_features


# =========================
# Configuration
# =========================

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

INTERFACE = (
    r"\Device\NPF_{0350BCF4-067A-46D6-A32F-C1D7309AF8A3}"
)

MODEL_PATH = r"..\ml\models\network_threat_rf_model.pkl"
FEATURES_PATH = r"..\ml\models\network_threat_feature_columns.pkl"
LABEL_MAP_PATH = r"..\ml\models\network_threat_label_map.pkl"

FLOW_TIMEOUT = 10


# =========================
# Load ML model
# =========================

print("Loading Random Forest model...")

model = joblib.load(MODEL_PATH)
feature_columns = joblib.load(FEATURES_PATH)
label_map = joblib.load(LABEL_MAP_PATH)

print("Model loaded successfully.")
print(f"Expected features: {len(feature_columns)}")


# =========================
# Flow storage
# =========================

flows = {}


def get_packet_info(packet):
    """Extract basic information from a PyShark packet."""

    if not hasattr(packet, "ip"):
        return None

    src_ip = packet.ip.src
    dst_ip = packet.ip.dst

    protocol = "OTHER"

    if hasattr(packet, "transport_layer"):
        protocol = packet.transport_layer

    src_port = 0
    dst_port = 0

    if hasattr(packet, "tcp"):
        src_port = int(packet.tcp.srcport)
        dst_port = int(packet.tcp.dstport)

    elif hasattr(packet, "udp"):
        src_port = int(packet.udp.srcport)
        dst_port = int(packet.udp.dstport)

    try:
        packet_length = int(packet.length)
    except Exception:
        packet_length = 0

    try:
        timestamp = float(packet.sniff_timestamp)
    except Exception:
        timestamp = time.time()

    flags = {}

    if hasattr(packet, "tcp"):

        tcp = packet.tcp

        flags = {
"FIN": 1 if str(getattr(tcp, "flags_fin", "False")).lower() == "true" else 0,
"SYN": 1 if str(getattr(tcp, "flags_syn", "False")).lower() == "true" else 0,
"RST": 1 if str(getattr(tcp, "flags_reset", "False")).lower() == "true" else 0,
"PSH": 1 if str(getattr(tcp, "flags_push", "False")).lower() == "true" else 0,
"ACK": 1 if str(getattr(tcp, "flags_ack", "False")).lower() == "true" else 0,
"URG": 1 if str(getattr(tcp, "flags_urg", "False")).lower() == "true" else 0,
            "CWE": 0,
"ECE": 1 if str(getattr(tcp, "flags_ece", "False")).lower() == "true" else 0,
        }

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "length": packet_length,
        "timestamp": timestamp,
        "header_length": 0,
        "flags": flags,
    }


def get_flow_key(packet_info):
    """
    Create a bidirectional flow key.

    The same connection in either direction
    should belong to one flow.
    """

    endpoint_a = (
        packet_info["src_ip"],
        packet_info["src_port"],
    )

    endpoint_b = (
        packet_info["dst_ip"],
        packet_info["dst_port"],
    )

    if endpoint_a <= endpoint_b:
        first = endpoint_a
        second = endpoint_b
    else:
        first = endpoint_b
        second = endpoint_a

    return (
        first,
        second,
        packet_info["protocol"],
    )


def create_flow(packet_info):
    """Create a new flow."""

    return {
        "destination_port": packet_info["dst_port"],
        "start_time": packet_info["timestamp"],
        "end_time": packet_info["timestamp"],

        "src_ip": packet_info["src_ip"],
        "dst_ip": packet_info["dst_ip"],

        "forward_packets": [],
        "backward_packets": [],

        "forward_src": packet_info["src_ip"],
        "forward_dst": packet_info["dst_ip"],

        "init_win_forward": 0,
        "init_win_backward": 0,
    }


def add_packet_to_flow(flow, packet_info):
    """Add packet to the correct direction."""

    flow["end_time"] = packet_info["timestamp"]

    packet = {
        "timestamp": packet_info["timestamp"],
        "length": packet_info["length"],
        "header_length": packet_info["header_length"],
        "flags": packet_info["flags"],
    }

    if (
        packet_info["src_ip"] == flow["forward_src"]
        and packet_info["dst_ip"] == flow["forward_dst"]
    ):
        flow["forward_packets"].append(packet)

    else:
        flow["backward_packets"].append(packet)


def predict_flow(flow):
    """Convert a completed flow into 78 features and predict."""

    features = build_features(flow)

    # Ensure exact model feature order
    X = pd.DataFrame(
        [[features[column] for column in feature_columns]],
        columns=feature_columns,
    )

    prediction = model.predict(X)[0]

    probabilities = model.predict_proba(X)[0]
    confidence = float(max(probabilities))

    print("\n===================================")
    print(" LIVE ML PREDICTION")
    print("===================================")

    print(
        f"Flow: "
        f"{flow['src_ip']} → {flow['dst_ip']}"
    )

    print(
        f"Packets: "
        f"{len(flow['forward_packets']) + len(flow['backward_packets'])}"
    )

    print(
        f"Prediction: {prediction}"
    )

    print(
        f"Confidence: {confidence:.2%}"
    )

    print("===================================\n")


def process_expired_flows():
    """Predict flows that have been inactive for FLOW_TIMEOUT seconds."""

    current_time = time.time()

    expired = []

    for key, flow in flows.items():

        if current_time - flow["end_time"] > FLOW_TIMEOUT:
            expired.append(key)

    for key in expired:

        flow = flows.pop(key)

        total_packets = (
            len(flow["forward_packets"])
            + len(flow["backward_packets"])
        )

        # Ignore completely empty flows
        if total_packets == 0:
            continue

        predict_flow(flow)


# =========================
# Start capture
# =========================

print("\n===================================")
print(" LIVE ML NETWORK MONITOR")
print("===================================")
print("Interface: Ethernet")
print("Flow timeout:", FLOW_TIMEOUT, "seconds")
print("Waiting for network traffic...\n")


capture = pyshark.LiveCapture(
    interface=INTERFACE,
    tshark_path=TSHARK_PATH,
)


try:

    last_cleanup = time.time()

    for packet in capture.sniff_continuously():

        packet_info = get_packet_info(packet)

        if packet_info is None:
            continue

        key = get_flow_key(packet_info)

        if key not in flows:
            flows[key] = create_flow(packet_info)

        add_packet_to_flow(
            flows[key],
            packet_info,
        )

        # Check expired flows periodically
        if time.time() - last_cleanup >= 2:

            process_expired_flows()

            last_cleanup = time.time()


except KeyboardInterrupt:

    print("\nStopping live ML monitor...")

finally:

    capture.close()