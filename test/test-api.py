import pyshark
import requests

# Thiết lập địa chỉ và cổng của webhook API
WEBHOOK_URL = 'http://your-webhook-url.com/api'

def packet_handler(packet):
    # Xử lý gói tin ở đây (ví dụ: lấy nội dung gói tin)
    packet_data = packet.hexdump  # Lấy dữ liệu gói tin dưới dạng hexdump

    # Gửi gói tin đến webhook API
    payload = {'data': packet_data}
    try:
        response = requests.post(WEBHOOK_URL, json=payload)
        print(f"Packet sent to webhook API. Response: {response.status_code}")
    except Exception as e:
        print(f"Error sending packet to webhook API: {e}")

# Bắt gói tin từ interface được chỉ định và áp dụng hàm xử lý
capture = pyshark.LiveCapture(interface='Wi-Fi')
for packet in capture.sniff_continuously():
    packet_handler(packet)
