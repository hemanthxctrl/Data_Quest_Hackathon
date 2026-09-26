import math
import statistics


def safe_mean(values):
    return statistics.mean(values) if values else 0.0


def safe_std(values):
    return statistics.stdev(values) if len(values) > 1 else 0.0


def safe_min(values):
    return min(values) if values else 0.0


def safe_max(values):
    return max(values) if values else 0.0


def calculate_iat(times):
    if len(times) < 2:
        return []

    return [
        times[i] - times[i - 1]
        for i in range(1, len(times))
    ]


def build_features(flow):
    """
    Convert one collected network flow into the
    CICIDS2017-style feature dictionary.

    Expected flow structure:

    {
        "destination_port": int,
        "forward_packets": [...],
        "backward_packets": [...],
        "start_time": float,
        "end_time": float
    }

    Each packet should contain:

    {
        "timestamp": float,
        "length": int,
        "header_length": int,
        "flags": {...}
    }
    """

    fwd = flow.get("forward_packets", [])
    bwd = flow.get("backward_packets", [])

    all_packets = fwd + bwd

    start_time = flow.get("start_time", 0.0)
    end_time = flow.get("end_time", start_time)

    duration = max(end_time - start_time, 0.0)

    fwd_lengths = [p["length"] for p in fwd]
    bwd_lengths = [p["length"] for p in bwd]
    all_lengths = [p["length"] for p in all_packets]

    fwd_times = [p["timestamp"] for p in fwd]
    bwd_times = [p["timestamp"] for p in bwd]
    all_times = [p["timestamp"] for p in all_packets]

    flow_iat = calculate_iat(all_times)
    fwd_iat = calculate_iat(fwd_times)
    bwd_iat = calculate_iat(bwd_times)

    total_fwd_bytes = sum(fwd_lengths)
    total_bwd_bytes = sum(bwd_lengths)

    total_packets = len(all_packets)

    flow_seconds = duration

    flow_bytes_per_sec = (
        (total_fwd_bytes + total_bwd_bytes) / flow_seconds
        if flow_seconds > 0
        else 0.0
    )

    flow_packets_per_sec = (
        total_packets / flow_seconds
        if flow_seconds > 0
        else 0.0
    )

    fwd_packets_per_sec = (
        len(fwd) / flow_seconds
        if flow_seconds > 0
        else 0.0
    )

    bwd_packets_per_sec = (
        len(bwd) / flow_seconds
        if flow_seconds > 0
        else 0.0
    )

    flags = {
        "FIN": 0,
        "SYN": 0,
        "RST": 0,
        "PSH": 0,
        "ACK": 0,
        "URG": 0,
        "CWE": 0,
        "ECE": 0,
    }

    fwd_psh = 0
    bwd_psh = 0
    fwd_urg = 0
    bwd_urg = 0

    for packet in fwd:
        packet_flags = packet.get("flags", {})

        for flag in flags:
            flags[flag] += int(packet_flags.get(flag, 0))

        fwd_psh += int(packet_flags.get("PSH", 0))
        fwd_urg += int(packet_flags.get("URG", 0))

    for packet in bwd:
        packet_flags = packet.get("flags", {})

        for flag in flags:
            flags[flag] += int(packet_flags.get(flag, 0))

        bwd_psh += int(packet_flags.get("PSH", 0))
        bwd_urg += int(packet_flags.get("URG", 0))

    fwd_headers = [
        p.get("header_length", 0)
        for p in fwd
    ]

    bwd_headers = [
        p.get("header_length", 0)
        for p in bwd
    ]

    total_fwd_header = sum(fwd_headers)
    total_bwd_header = sum(bwd_headers)

    avg_packet_size = (
        safe_mean(all_lengths)
    )

    down_up_ratio = (
        len(bwd) / len(fwd)
        if len(fwd) > 0
        else 0.0
    )

    features = {

        "Destination Port":
            flow.get("destination_port", 0),

        "Flow Duration":
            duration,

        "Total Fwd Packets":
            len(fwd),

        "Total Backward Packets":
            len(bwd),

        "Total Length of Fwd Packets":
            total_fwd_bytes,

        "Total Length of Bwd Packets":
            total_bwd_bytes,

        "Fwd Packet Length Max":
            safe_max(fwd_lengths),

        "Fwd Packet Length Min":
            safe_min(fwd_lengths),

        "Fwd Packet Length Mean":
            safe_mean(fwd_lengths),

        "Fwd Packet Length Std":
            safe_std(fwd_lengths),

        "Bwd Packet Length Max":
            safe_max(bwd_lengths),

        "Bwd Packet Length Min":
            safe_min(bwd_lengths),

        "Bwd Packet Length Mean":
            safe_mean(bwd_lengths),

        "Bwd Packet Length Std":
            safe_std(bwd_lengths),

        "Flow Bytes/s":
            flow_bytes_per_sec,

        "Flow Packets/s":
            flow_packets_per_sec,

        "Flow IAT Mean":
            safe_mean(flow_iat),

        "Flow IAT Std":
            safe_std(flow_iat),

        "Flow IAT Max":
            safe_max(flow_iat),

        "Flow IAT Min":
            safe_min(flow_iat),

        "Fwd IAT Total":
            sum(fwd_iat),

        "Fwd IAT Mean":
            safe_mean(fwd_iat),

        "Fwd IAT Std":
            safe_std(fwd_iat),

        "Fwd IAT Max":
            safe_max(fwd_iat),

        "Fwd IAT Min":
            safe_min(fwd_iat),

        "Bwd IAT Total":
            sum(bwd_iat),

        "Bwd IAT Mean":
            safe_mean(bwd_iat),

        "Bwd IAT Std":
            safe_std(bwd_iat),

        "Bwd IAT Max":
            safe_max(bwd_iat),

        "Bwd IAT Min":
            safe_min(bwd_iat),

        "Fwd PSH Flags":
            fwd_psh,

        "Bwd PSH Flags":
            bwd_psh,

        "Fwd URG Flags":
            fwd_urg,

        "Bwd URG Flags":
            bwd_urg,

        "Fwd Header Length":
            total_fwd_header,

        "Bwd Header Length":
            total_bwd_header,

        "Fwd Packets/s":
            fwd_packets_per_sec,

        "Bwd Packets/s":
            bwd_packets_per_sec,

        "Min Packet Length":
            safe_min(all_lengths),

        "Max Packet Length":
            safe_max(all_lengths),

        "Packet Length Mean":
            safe_mean(all_lengths),

        "Packet Length Std":
            safe_std(all_lengths),

        "Packet Length Variance":
            (
                statistics.variance(all_lengths)
                if len(all_lengths) > 1
                else 0.0
            ),

        "FIN Flag Count":
            flags["FIN"],

        "SYN Flag Count":
            flags["SYN"],

        "RST Flag Count":
            flags["RST"],

        "PSH Flag Count":
            flags["PSH"],

        "ACK Flag Count":
            flags["ACK"],

        "URG Flag Count":
            flags["URG"],

        "CWE Flag Count":
            flags["CWE"],

        "ECE Flag Count":
            flags["ECE"],

        "Down/Up Ratio":
            down_up_ratio,

        "Average Packet Size":
            avg_packet_size,

        "Avg Fwd Segment Size":
            safe_mean(fwd_lengths),

        "Avg Bwd Segment Size":
            safe_mean(bwd_lengths),

        "Fwd Header Length.1":
            total_fwd_header,

        # These bulk features require additional
        # CICFlowMeter-style bulk detection.
        "Fwd Avg Bytes/Bulk":
            0.0,

        "Fwd Avg Packets/Bulk":
            0.0,

        "Fwd Avg Bulk Rate":
            0.0,

        "Bwd Avg Bytes/Bulk":
            0.0,

        "Bwd Avg Packets/Bulk":
            0.0,

        "Bwd Avg Bulk Rate":
            0.0,

        "Subflow Fwd Packets":
            len(fwd),

        "Subflow Fwd Bytes":
            total_fwd_bytes,

        "Subflow Bwd Packets":
            len(bwd),

        "Subflow Bwd Bytes":
            total_bwd_bytes,

        "Init_Win_bytes_forward":
            flow.get("init_win_forward", 0),

        "Init_Win_bytes_backward":
            flow.get("init_win_backward", 0),

        "act_data_pkt_fwd":
            sum(
                1
                for p in fwd
                if p["length"] > 0
            ),

        "min_seg_size_forward":
            safe_min(fwd_lengths),

        # Active/Idle require timeout-based
        # flow state tracking.
        "Active Mean":
            0.0,

        "Active Std":
            0.0,

        "Active Max":
            0.0,

        "Active Min":
            0.0,

        "Idle Mean":
            0.0,

        "Idle Std":
            0.0,

        "Idle Max":
            0.0,

        "Idle Min":
            0.0,
    }

    return features
    