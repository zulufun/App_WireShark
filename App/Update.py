import tkinter as tk
from tkinter import scrolledtext, filedialog, ttk, messagebox
import pyshark
import threading
import csv
import requests

# Thêm tính năng lấy thông tin của địa chỉ IP
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

        # Menu
        self.menu = tk.Menu(master)
        master.config(menu=self.menu)
        self.file_menu = tk.Menu(self.menu, tearoff=False)
        self.menu.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="Open", command=self.open_file)
        self.file_menu.add_command(label="Save to CSV", command=self.save_to_csv)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=master.quit)

        self.help_menu = tk.Menu(self.menu, tearoff=False)
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
        self.continue_button = tk.Button(self.interface_frame, text="Continue", command=self.continue_capture, state=tk.DISABLED)
        self.continue_button.grid(row=0, column=4, padx=5)
        self.export_button = tk.Button(self.interface_frame, text="Export to CSV", command=self.export_to_csv, state=tk.DISABLED)
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
        self.tree = ttk.Treeview(master, columns=("No.", "Time", "Source", "Destination", "Protocol", "Length", "Src_Country", "Src_City", "Src_Time_Zone", "Src_Service"), show="headings")
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
        self.filtered_packets = []

    def start_filter_thread(self):
        filter_field = self.filter_field_combobox.get()
        filter_text = self.filter_entry.get()
        self.filter_thread = threading.Thread(target=self.filter_packets, args=(filter_field, filter_text))
        self.filter_thread.start()

    def filter_packets(self, filter_field, filter_text):
        self.filtered_packets = []
        for packet in self.packet_list:
            if filter_field == "Source IP":
                if hasattr(packet, 'ip'):
                    if packet.ip.src == filter_text:
                        self.filtered_packets.append(packet)
            elif filter_field == "Destination IP":
                if hasattr(packet, 'ip'):
                    if packet.ip.dst == filter_text:
                        self.filtered_packets.append(packet)
            elif filter_field == "Protocol":
                if hasattr(packet, 'transport_layer'):
                    if packet.transport_layer == filter_text:
                        self.filtered_packets.append(packet)

        self.display_packets(self.filtered_packets)

    def display_packets(self, packets):
        self.tree.delete(*self.tree.get_children())

        for idx, packet in enumerate(packets, start=1):
            if 'ip' in packet:
                source_ip = packet.ip.src
                dest_ip = packet.ip.dst
                source_geo = IPGeolocation(source_ip)
                dest_geo = IPGeolocation(dest_ip)
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
            self.tree.insert("", "end", values=(
                len(self.packet_list),
                packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S'),
                packet.ip.src if 'ip' in packet else '',
                packet.ip.dst if 'ip' in packet else '',
                packet.transport_layer if hasattr(packet, 'transport_layer') else '',
                packet.length,
                IPGeolocation(packet.ip.src).country if 'ip' in packet else '',
                IPGeolocation(packet.ip.src).city if 'ip' in packet else '',
                IPGeolocation(packet.ip.src).time_zone if 'ip' in packet else '',
                IPGeolocation(packet.ip.src).isp if 'ip' in packet else ''
            ))

    def display_packet_details(self, event):
        item = self.tree.selection()
        if item:
            item = item[0]
            packet = self.packet_list[int(self.tree.item(item, "values")[0]) - 1]
            self.log.delete(1.0, tk.END)
            self.log.insert(tk.END, str(packet))

    def export_to_csv(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if file_path:
            try:
                with open(file_path, mode='w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(["No.", "Time", "Source", "Destination", "Protocol", "Length", "Src_Country", "Src_City", "Src_Time_Zone", "Src_Service"])
                    for idx, packet in enumerate(self.packet_list, start=1):
                        if 'ip' in packet:
                            source_ip = packet.ip.src
                            dest_ip = packet.ip.dst
                            source_geo = IPGeolocation(source_ip)
                            writer.writerow([idx, packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S'), source_ip, dest_ip, packet.transport_layer, packet.length, source_geo.country, source_geo.city, source_geo.time_zone, source_geo.isp])
                self.log.insert(tk.END, "Data exported to {}\n".format(file_path))
            except Exception as e:
                self.log.insert(tk.END, "Error exporting to CSV: {}\n".format(e))

    def open_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        if file_path:
            try:
                self.capture = pyshark.FileCapture(file_path)
                self.log.insert(tk.END, "Opened file: {}\n".format(file_path))
                self.start_button.config(state=tk.DISABLED)
                self.stop_button.config(state=tk.DISABLED)
                self.continue_button.config(state=tk.DISABLED)
                self.export_button.config(state=tk.NORMAL)

                self.packet_list.clear()
                self.display_packets(self.capture)
            except Exception as e:
                self.log.insert(tk.END, "Error opening file: {}\n".format(e))

    def save_to_csv(self):
        self.export_to_csv()

    def show_help_message(self):
        help_text = (
            "Wireshark App Help\n"
            "====================\n"
            "1. Select interface and click Start to start capturing packets.\n"
            "2. Click Stop to stop capturing.\n"
            "3. Click Continue to resume capturing.\n"
            "4. Use Filter to filter packets by Source IP, Destination IP, or Protocol.\n"
            "5. Use the File menu to open a PCAP file or save captured data to a CSV file.\n"
            "6. Click on a packet to see its details."
        )
        messagebox.showinfo("Help", help_text)

def main():
    root = tk.Tk()
    app = WiresharkApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
