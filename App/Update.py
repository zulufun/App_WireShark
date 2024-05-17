import tkinter as tk
from tkinter import scrolledtext, filedialog, ttk, Menu, messagebox
import pyshark
import threading
import csv
import geoip2.database
import requests
import dpkt
import socket

# Thêm tính năng lấy thông tin của địa chi IP
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
        master.title("Packet Capture App")
        # Menu
        self.menu = Menu(master)
        master.config(menu=self.menu)

        # Menu File
        self.file_menu = Menu(self.menu)
        self.menu.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="Open", command=self.open_file)
        self.file_menu.add_command(label="Save", command=self.save_to_csv)

        # Menu Help
        self.help_menu = Menu(self.menu)
        self.menu.add_cascade(label="Help", menu=self.help_menu)
        self.help_menu.add_command(label="About", command=self.show_help_message)

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

        # Định nghĩa chiều rộng mặc định cho từng cột
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
            "Src_Service": 100,
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

    def start_filter_thread(self):
        filter_field = self.filter_field_combobox.get()
        filter_text = self.filter_entry.get()
        self.filter_thread = threading.Thread(target=self.filter_packets, args=(filter_field, filter_text))
        self.filter_thread.start()

    def filter_packets(self, filter_field, filter_text):
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

        self.tree.delete(*self.tree.get_children())

        for idx, packet in enumerate(filtered_packets, start=1):
            self.tree.insert("", "end", values=(
                idx,
                packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S'),
                packet.ip.src if hasattr(packet, 'ip') else '',
                packet.ip.dst if hasattr(packet, 'ip') else '',
                packet.transport_layer if hasattr(packet, 'transport_layer') else '',
                packet.length if hasattr(packet, 'length') else ''
            ))

        self.scrollbar = ttk.Scrollbar(self.master, orient="vertical", command=self.tree.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=self.scrollbar.set)

    def start_capture(self):
        if not self.running:
            interface = self.interface_combobox.get()
            try:
                self.capture = pyshark.LiveCapture(interface=interface)
                self.packet_list.clear()
                self.tree.delete(*self.tree.get_children())  # Clear previous entries in the treeview
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
            interface = self.interface_combobox.get()
            try:
                self.capture = pyshark.LiveCapture(interface=interface)
                self.log.insert(tk.END, "Continued capturing on interface: {}\n".format(interface))
                self.start_button.config(state=tk.DISABLED)
                self.stop_button.config(state=tk.NORMAL)
                self.continue_button.config(state=tk.DISABLED)
                self.export_button.config(state=tk.DISABLED)

                self.running = True
                self.capture_thread = threading.Thread(target=self.capture_packets)
                self.capture_thread.start()
            except Exception as e:
                self.log.insert(tk.END, "Error: {}\n".format(e))

    def capture_packets(self):
        try:
            for packet in self.capture.sniff_continuously():
                if not self.running:
                    break
                self.packet_list.append(packet)
                self.add_packet_to_tree(packet)
        except Exception as e:
            self.log.insert(tk.END, "Error capturing packets: {}\n".format(e))

    def add_packet_to_tree(self, packet):
        # Lấy thông tin của địa chỉ IP nguồn từ gói tin
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            geolocation = IPGeolocation(src_ip)
            src_country = geolocation.country
            src_city = geolocation.city
            src_time_zone = geolocation.time_zone
            src_service = geolocation.isp
        else:
            src_country = ''
            src_city = ''
            src_time_zone = ''
            src_service = ''

        packet_info = (
            len(self.packet_list),
            packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S'),
            packet.ip.src if hasattr(packet, 'ip') else '',
            packet.ip.dst if hasattr(packet, 'ip') else '',
            packet.transport_layer if hasattr(packet, 'transport_layer') else '',
            packet.length if hasattr(packet, 'length') else '',
            src_country,
            src_city,
            src_time_zone,
            src_service
        )
        self.tree.insert("", "end", values=packet_info)

    def open_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])
        if file_path:
            self.tree.delete(*self.tree.get_children())
            self.log.insert(tk.END, "Opened file: {}\n".format(file_path))
            open_thread = threading.Thread(target=self.read_pcap_file, args=(file_path,))
            open_thread.start()

    def read_pcap_file(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                for idx, (timestamp, buf) in enumerate(pcap, start=1):
                    eth = dpkt.ethernet.Ethernet(buf)
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data
                        src_ip = socket.inet_ntoa(ip.src)
                        dst_ip = socket.inet_ntoa(ip.dst)
                        geolocation = IPGeolocation(src_ip)
                        src_country = geolocation.country
                        src_city = geolocation.city
                        src_time_zone = geolocation.time_zone
                        src_service = geolocation.isp
                        packet_info = (
                            idx,
                            timestamp,
                            src_ip,
                            dst_ip,
                            ip.p,
                            len(buf),
                            src_country,
                            src_city,
                            src_time_zone,
                            src_service
                        )
                        self.tree.insert("", "end", values=packet_info)
        except Exception as e:
            self.log.insert(tk.END, "Error reading file: {}\n".format(e))

    def save_to_csv(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                                 filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if file_path:
            self.export_to_csv(file_path)

    def export_to_csv(self, file_path=""):
        if not file_path:
            file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                                     filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if file_path:
            try:
                with open(file_path, mode='w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(
                        ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Src_Country", "Src_City",
                         "Src_Time_Zone", "Src_Service"])
                    for row in self.tree.get_children():
                        writer.writerow(self.tree.item(row)['values'])
                self.log.insert(tk.END, "Exported to {}\n".format(file_path))
            except Exception as e:
                self.log.insert(tk.END, "Error exporting to CSV: {}\n".format(e))

    def display_packet_details(self, event):
        selected_item = self.tree.selection()
        if selected_item:
            packet_details = self.tree.item(selected_item)["values"]
            details = "Packet Details:\n"
            details += "\n".join(f"{self.tree.heading(col, 'text')}: {val}" for col, val in zip(self.tree["columns"], packet_details))
            messagebox.showinfo("Packet Details", details)

    def show_help_message(self):
        help_message = "Packet Capture App\n\n" \
                       "This application allows you to capture and analyze network packets.\n\n" \
                       "Use the 'File' menu to open a PCAP file or save captured packets to a CSV file.\n\n" \
                       "Use the 'Help' menu to view this help message."
        messagebox.showinfo("About", help_message)


if __name__ == "__main__":
    root = tk.Tk()
    app = WiresharkApp(root)
    root.mainloop()
