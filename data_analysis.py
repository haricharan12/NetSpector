from scapy.all import *
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import ipaddress
import pandas as pd
from datetime import datetime

def read_packets(file_name):
    return rdpcap(file_name)

def extract_features(packets):
    features = []
    packet_details = []

    for packet in packets:
        # Convert packet.time to a float
        timestamp = datetime.fromtimestamp(float(packet.time)).strftime('%Y-%m-%d %H:%M:%S')
        src_ip, dst_ip, src_port, dst_port, protocol = 'N/A', 'N/A', 0, 0, 'UNKNOWN'

        if IP in packet:
            src_ip = int(ipaddress.IPv4Address(packet[IP].src))
            dst_ip = int(ipaddress.IPv4Address(packet[IP].dst))
            src_port = packet[TCP].sport if TCP in packet else 0
            dst_port = packet[TCP].dport if TCP in packet else 0
            protocol = packet[IP].proto

        packet_length = len(packet)
        features.append([src_ip, dst_ip, src_port, dst_port, packet_length])
        packet_details.append([timestamp, packet[IP].src, packet[IP].dst, src_port, dst_port, protocol])

    return features, packet_details

def preprocess_data(features):
    scaler = StandardScaler()
    standardized_features = scaler.fit_transform(features)
    return standardized_features

def detect_anomalies(standardized_features):
    iso_forest = IsolationForest(n_estimators=100, contamination=0.01)
    anomalies = iso_forest.fit_predict(standardized_features)
    return anomalies == -1  # -1 indicates an anomaly

def save_anomaly_details(packet_details, anomalies, output_file):
    anomaly_data = pd.DataFrame(packet_details, columns=['Timestamp', 'Source_IP', 'Destination_IP', 'Source_Port', 'Destination_Port', 'Protocol'])
    anomaly_data['Anomaly'] = anomalies
    anomaly_data.to_csv(output_file, index=False)

def main():
    pcap_file = "packets_data.pcap"
    output_file = "anomalies.csv"

    packets = read_packets(pcap_file)
    features, packet_details = extract_features(packets)
    standardized_features = preprocess_data(features)
    anomalies = detect_anomalies(standardized_features)

    save_anomaly_details(packet_details, anomalies, output_file)
    print(f"Analysis complete. Anomaly details saved to {output_file}")

if __name__ == "__main__":
    main()
