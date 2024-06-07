import pyshark
import numpy as np
from setfit import SetFitModel

# Load the Isolation Forest model from Hugging Face
model = SetFitModel.from_pretrained("isolation-forest/setfit-absa-aspect")

# Function to extract features from a packet
def extract_features(packet):
    # Extract relevant features from the packet
    features = [
        packet.ip.src,      # Source IP address
        packet.ip.dst,      # Destination IP address
        packet.tcp.srcport, # Source port
        packet.tcp.dstport, # Destination port
        packet.length      # Packet length
    ]
    return features

# Function to preprocess the data
def preprocess_data(packets):
    # Extract features from each packet
    data = [extract_features(packet) for packet in packets]
    # Convert data to numpy array
    return np.array(data)

# Function to detect anomalies using the Isolation Forest model
def detect_anomalies(data):
    # Preprocess the data
    processed_data = preprocess_data(data)
    # Predict anomalies using the Isolation Forest model
    anomalies = model.predict(processed_data)
    return anomalies

# Function to capture packets and detect anomalies
def capture_and_detect(interface, num_packets):
    # Create a packet capture object
    capture = pyshark.LiveCapture(interface=interface, display_filter='tcp')
    # Start capturing packets
    capture.sniff(timeout=num_packets)
    # Extract packet data
    packets = [packet for packet in capture]
    # Detect anomalies
    anomalies = detect_anomalies(packets)
    # Print detected anomalies
    print("Detected anomalies:")
    for i, anomaly in enumerate(anomalies):
        if anomaly == -1:
            print(f"Anomaly detected in packet {i+1}")

# Main function
if __name__ == "__main__":
    interface = 'Wi-Fi'  # Change this to your network interface
    num_packets = 100  # Number of packets to capture
    capture_and_detect(interface, num_packets)
