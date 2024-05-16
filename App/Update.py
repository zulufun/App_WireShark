import tkinter as tk
from tkinter import scrolledtext, filedialog, ttk
import pyshark
import threading
import csv
import geoip2.database
import requests
import dpkt
import socket

#Thêm tính năng lấy thông tin của địa chi IP
class IPGeolocation(object):
    def __init__(self, ip_address):
        self.latitude = ''
        self.longitude = ''
        self.country = ''
        self.city = ''
        self.time_zone = ''
        self.isp = ''
        self.ip_address = ip_address
        self.get_location()

    def get_location(self):
        json_request = requests.get(f'http://ip-api.com/json/{self.ip_address}').json()
        if 'country' in json_request:
            self.country = json_request['country']
        if 'city' in json_request:
            self.city = json_request['city']
        if 'timezone' in json_request:
            self.time_zone = json_request['timezone']
        if 'lat' in json_request:
            self.latitude = json_request['lat']
        if 'lon' in json_request:
            self.longitude = json_request['lon']
        if 'isp' in json_request:
            self.isp = json_request['isp']

class WiresharkApp:
    def __init__(self, master):
        self.master = master
        master.title("Wireshark App")
        # Frame chứa phần nhập liệu và nút bắt đầu
        self.interface_frame = tk.Frame(master)
        self.interface_frame.pack(pady=10)

        self.label = tk.Label(self.interface_frame, text="Select interface:")
        self.label.grid(row=0, column=0, padx=5)

        # Sử dụng Combobox với các giá trị sẵn
        self.interface_combobox = ttk.Combobox(self.interface_frame, values=["Wi-Fi", "Bluetooth"])
        self.interface_combobox.grid(row=0, column=1, padx=5)
        self.interface_combobox.current(0)  # Thiết lập giá trị mặc định

        self.start_button = tk.Button(self.interface_frame, text="Start", command=self.start_capture)
        self.start_button.grid(row=0, column=2, padx=5)
        self.stop_button = tk.Button(self.interface_frame, text="Stop", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=3, padx=5)
        self.continue_button = tk.Button(self.interface_frame, text="Continue", command=self.continue_capture,
                                         state=tk.DISABLED)
        self.continue_button.grid(row=0, column=4, padx=5)
        self.export_button = tk.Button(self.interface_frame, text="Export to CSV", command=self.export_to_csv,
                                       state=tk.DISABLED)
        self.export_button.grid(row=0, column=5, padx=5)
        # Phần Filter
        self.filter_frame = tk.Frame(master)
        self.filter_frame.pack(pady=10)

        self.filter_field_label = tk.Label(self.filter_frame, text="Filter Field:")
        self.filter_field_label.grid(row=0, column=0, padx=5)

        self.filter_field_combobox = ttk.Combobox(self.filter_frame, values=["Source IP", "Destination IP", "Protocol"])
        self.filter_field_combobox.grid(row=0, column=1, padx=5)

        self.filter_entry_label = tk.Label(self.filter_frame, text="Filter Text:")
        self.filter_entry_label.grid(row=0, column=2, padx=5)

        self.filter_entry = tk.Entry(self.filter_frame)
        self.filter_entry.grid(row=0, column=3, padx=5)

        self.filter_button = tk.Button(self.filter_frame, text="Filter", command=self.start_filter_thread)
        self.filter_button.grid(row=0, column=4, padx=5)
        # Treeview để hiển thị các gói tin
        self.tree = ttk.Treeview(master, columns=(
        "No.", "Time", "Source", "Destination", "Protocol", "Length", "Src_Country", "Src_City",
        "Src_Time_Zone", "Src_Service"), show="headings")
        self.tree.heading("No.", text="No.")
        self.tree.heading("Time", text="Time")
        self.tree.heading("Source", text="Source")
        self.tree.heading("Destination", text="Destination")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Length", text="Length")

        self.tree.heading("Src_Country", text="Src_Country")
        self.tree.heading("Src_City", text="Src_City")
        self.tree.heading("Src_Time_Zone", text="Src_Time Zone")
        self.tree.heading("Src_Service", text="Src_Service")

        # Định nghĩa chiều rộng mặc định cho từng cột (tên cột, chiều rộng)
        column_widths = {
            "No.": 50,
            "Time": 150,
            "Source": 100,
            "Destination": 100,
            "Protocol": 80,
            "Length": 80,
            "Src_Country": 100,
            "Src_City": 100,
            "Src_Time_Zone": 100,
            "Src_Service":100,
        }
        # Thiết lập chiều rộng cho từng cột
        for column, width in column_widths.items():
            self.tree.column(column, width=width, anchor=tk.CENTER)

        self.tree.bind("<ButtonRelease-1>", self.display_packet_details)  # Bắt sự kiện click chuột
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Scrollbar cho Treeview
        self.scrollbar = ttk.Scrollbar(master, orient="vertical", command=self.tree.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=self.scrollbar.set)
        # Log ScrolledText widget
        self.log = scrolledtext.ScrolledText(master, width=60, height=10)
        self.log.pack(fill=tk.BOTH, expand=True)
        self.capture = None
        self.capture_thread = None
        self.running = False
        self.packet_list = []
        ################Fillter#########################


        # Thêm hàm start_filter_thread để chạy Filter trong một luồng Thread

    def start_filter_thread(self):
        filter_field = self.filter_field_combobox.get()
        filter_text = self.filter_entry.get()
        self.filter_thread = threading.Thread(target=self.filter_packets, args=(filter_field, filter_text))
        self.filter_thread.start()

        # Thêm hàm filter_packets để thực hiện Filter

    def filter_packets(self, filter_field, filter_text):
        # Thực hiện Filter ở đây
        # Đảm bảo chỉ sử dụng các biến cục bộ và không thực hiện thay đổi trực tiếp trên giao diện
        # Sau khi hoàn thành, sử dụng self.master.after để cập nhật giao diện

        # Ví dụ về cách thực hiện Filter:
        filtered_packets = []
        for packet in self.packet_list:
            if filter_field == "Source IP":
                if hasattr(packet, 'ip'):
                    if packet.ip.src == filter_text:
                        filtered_packets.append(packet)
            elif filter_field == "Destination IP":
                if hasattr(packet, 'ip'):
                    if packet.ip.dst == filter_text:
                        filtered_packets.append(packet)
            elif filter_field == "Protocol":
                if hasattr(packet, 'transport_layer'):
                    if packet.transport_layer == filter_text:
                        filtered_packets.append(packet)

        # Xóa tất cả các dòng trong Treeview
        self.tree.delete(*self.tree.get_children())

        # Hiển thị các gói tin đã lọc
        for idx, packet in enumerate(filtered_packets, start=1):
            # Thêm thông tin vào Treeview
            self.tree.insert("", "end", values=(
                idx,
                packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S'),
                packet.ip.src if hasattr(packet, 'ip') else '',
                packet.ip.dst if hasattr(packet, 'ip') else '',
                packet.transport_layer if hasattr(packet, 'transport_layer') else '',
                packet.length if hasattr(packet, 'length') else ''
            ))

        # Thêm thanh scrollbar
        self.scrollbar = ttk.Scrollbar(self.master, orient="vertical", command=self.tree.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=self.scrollbar.set)
        #####################End Fillter############################

    def start_capture(self):
        if not self.running:
            interface = self.interface_combobox.get()
            try:
                self.capture = pyshark.LiveCapture(interface=interface)
                self.log.insert(tk.END, "Started capturing on interface: {}\n".format(interface))
                self.start_button.config(state=tk.DISABLED)
                self.stop_button.config(state=tk.NORMAL)
                self.continue_button.config(state=tk.DISABLED)
                self.export_button.config(state=tk.DISABLED)

                self.running = True
                self.capture_thread = threading.Thread(target=self.capture_packets)
                self.capture_thread.start()
            except Exception as e:
                self.log.insert(tk.END, "Error: {}\n".format(e))

    def stop_capture(self):
        if self.running:
            self.running = False
            if self.capture:
                self.capture.close()
            self.log.insert(tk.END, "Capture stopped\n")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.continue_button.config(state=tk.NORMAL)
            self.export_button.config(state=tk.NORMAL)

    def continue_capture(self):
        if not self.running:
            self.running = True
            self.capture_thread = threading.Thread(target=self.capture_packets)
            self.capture_thread.start()
            self.log.insert(tk.END, "Capture resumed\n")
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.continue_button.config(state=tk.DISABLED)
            self.export_button.config(state=tk.DISABLED)

    def capture_packets(self):
        for idx, packet in enumerate(self.capture.sniff_continuously(), start=1):
            if not self.running:
                break
            self.packet_list.append(packet)
            # Thêm thông tin vào Treeview
            # self.tree.insert("", "end", values=(idx, packet.sniff_time, packet.ip.src, packet.ip.dst, packet.transport_layer, packet.length, packet.layers[1].layer_name))
            #Fix lại tính năng hiên thị thông tin ip
            if 'ip' in packet:
                source_ip = packet.ip.src
                dest_ip = packet.ip.dst
                # Tạo các đối tượng IPGeolocation để lấy thông tin địa lý
                source_geo = IPGeolocation(source_ip)
                dest_geo = IPGeolocation(dest_ip)
                # Thêm thông tin vào Treeview
                self.tree.insert("", "end", values=(
                    idx,
                    packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S'),
                    source_ip,
                    dest_ip,
                    packet.transport_layer,
                    packet.length,
                    source_geo.country,
                    source_geo.city,
                    source_geo.time_zone,
                    source_geo.isp
                ))
    def display_packet_details(self, event):
        item = self.tree.selection()
        if item:  # Kiểm tra xem có dòng nào được chọn không
            item = item[0]
            packet = self.packet_list[int(self.tree.item(item, "values")[0]) - 1]
            #Fix tính năng
            # Lấy thông tin địa lý của địa chỉ IP nguồn và đích của gói tin
            # source_ip = packet.ip.src
            # dest_ip = packet.ip.dst
            # source_geo = IPGeolocation(source_ip)
            # dest_geo = IPGeolocation(dest_ip)
            #Call Api khiến app bị delay khi hiển thị chi tiết gói tin
            ####################
            self.log.delete(1.0, tk.END)  # Xóa nội dung hiện tại
            self.log.insert(tk.END, str(packet))  # Hiển thị thông tin chi tiết của packet

    def export_to_csv(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if file_path:
            try:
                with open(file_path, mode='w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(["No.", "Time", "Source", "Destination", "Protocol", "Length"])
                    for idx, packet in enumerate(self.packet_list, start=1):
                        writer.writerow([idx, packet.sniff_time, packet.ip.src, packet.ip.dst, packet.transport_layer, packet.length])
                self.log.insert(tk.END, "Data exported to {}\n".format(file_path))
            except Exception as e:
                self.log.insert(tk.END, "Error exporting to CSV: {}\n".format(e))

def main():
    root = tk.Tk()
    app = WiresharkApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
