import pandas as pd
import numpy as np
import os

def generate_network_data(samples=5000):
    np.random.seed(42)
    
    # 70% Benign, 10% DDoS, 10% PortScan, 10% BruteForce
    labels = np.random.choice(
        ['BENIGN', 'DDoS', 'PORT_SCAN', 'BRUTE_FORCE'], 
        samples, 
        p=[0.7, 0.1, 0.1, 0.1]
    )
    
    data = []
    for label in labels:
        if label == 'BENIGN':
            flow_duration = np.random.normal(500, 100)
            fwd_packets = np.random.normal(10, 3)
            bwd_packets = np.random.normal(10, 3)
            flow_bytes_s = np.random.normal(1000, 200)
            flow_packets_s = np.random.normal(50, 10)
        elif label == 'DDoS':
            flow_duration = np.random.normal(10, 2) # Very short flows
            fwd_packets = np.random.normal(100, 20) # Many packets
            bwd_packets = np.random.normal(2, 1)
            flow_bytes_s = np.random.normal(50000, 10000) # High bandwidth
            flow_packets_s = np.random.normal(10000, 2000) # High packet rate
        elif label == 'PORT_SCAN':
            flow_duration = np.random.normal(5, 1) # Tiny flows
            fwd_packets = np.random.normal(1, 0.2) # Single packet
            bwd_packets = np.random.normal(1, 0.2)
            flow_bytes_s = np.random.normal(50, 10) # Low bytes
            flow_packets_s = np.random.normal(2, 1)
        elif label == 'BRUTE_FORCE':
            flow_duration = np.random.normal(2000, 500) # Long flows
            fwd_packets = np.random.normal(50, 10)
            bwd_packets = np.random.normal(80, 15)
            flow_bytes_s = np.random.normal(5000, 1000)
            flow_packets_s = np.random.normal(100, 20)
            
        data.append([
            max(0, flow_duration), 
            max(0, fwd_packets), 
            max(0, bwd_packets), 
            max(0, flow_bytes_s), 
            max(0, flow_packets_s), 
            label
        ])
        
    df = pd.DataFrame(data, columns=[
        'Flow Duration', 
        'Total Fwd Packets', 
        'Total Backward Packets', 
        'Flow Bytes/s', 
        'Flow Packets/s', 
        'Label'
    ])
    
    # Save dataset
    os.makedirs('ml/data/raw', exist_ok=True)
    file_path = 'ml/data/raw/synthetic_network_traffic.csv'
    df.to_csv(file_path, index=False)
    print(f"Dataset generated at {file_path}")

if __name__ == "__main__":
    generate_network_data()
