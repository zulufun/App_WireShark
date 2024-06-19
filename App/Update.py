import tkinter as tk
from tkinter import scrolledtext, filedialog, ttk, messagebox
from PIL import Image, ImageTk
import pyshark
import threading
import csv
import requests
import matplotlib.pyplot as plt
import asyncio
import psutil  # Thêm thư viện psutil
from scapy.all import wrpcap
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether


class IPGeolocation:
    cache = {}

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
        if self.ip_address in IPGeolocation.cache:
            geo_data = IPGeolocation.cache[self.ip_address]
        else:
            try:
                json_request = requests.get(f'http://ip-api.com/json/{self.ip_address}').json()
                geo_data = {
                    'country': json_request.get('country', ''),
                    'city': json_request.get('city', ''),
                    'timezone': json_request.get('timezone', ''),
                    'lat': json_request.get('lat', ''),
                    'lon': json_request.get('lon', ''),
                    'isp': json_request.get('isp', '')
                }
                IPGeolocation.cache[self.ip_address] = geo_data
            except requests.RequestException as e:
                print(f"Error fetching geolocation data: {e}")
                geo_data = {
                    'country': '',
                    'city': '',
                    'timezone': '',
                    'lat': '',
                    'lon': '',
                    'isp': ''
                }

        self.country = geo_data['country']
        self.city = geo_data['city']
        self.time_zone = geo_data['timezone']
        self.latitude = geo_data['lat']
        self.longitude = geo_data['lon']
        self.isp = geo_data['isp']

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
        self.file_menu.add_command(label="Save to PCAP", command=self.save_to_pcap)
        self.file_menu.add_command(label="Save to CSV", command=self.save_to_csv)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=master.quit)

        self.help_menu = tk.Menu(self.menu, tearoff=False)
        self.menu.add_cascade(label="Help", menu=self.help_menu)
        self.help_menu.add_command(label="About", command=self.show_help_message)

        # Stats Menu
        self.stats_menu = tk.Menu(self.menu, tearoff=False)
        self.menu.add_cascade(label="Stats", menu=self.stats_menu)
        self.stats_menu.add_command(label="Source Country Distribution", command=self.show_source_country_stats)
        self.stats_menu.add_command(label="Source Service Distribution", command=self.show_source_service_stats)

        # Logo và tiêu đề
        self.top_frame = tk.Frame(master)
        self.top_frame.pack(pady=10)

        # Tải và hiển thị logo
        self.logo_image = Image.open('D:/Python_NETWORKING_CODE/BTLon/CD1/App/Logo_MTA_new.png')
        self.logo_image = self.logo_image.resize((80, 80), Image.LANCZOS)
        self.logo_photo = ImageTk.PhotoImage(self.logo_image)
        self.logo_label = tk.Label(self.top_frame, image=self.logo_photo)
        self.logo_label.grid(row=0, column=0, padx=(0, 50), sticky="w")  # Sát về bên trái

        self.title_label = tk.Label(self.top_frame, text="Phân tích mạng K56", font=("Arial", 24))
        self.title_label.grid(row=0, column=1, padx=10, columnspan=2)  # Căn giữa

        self.top_frame.pack(pady=10)
#######################################
        # Frame for interface selection and control buttons
        self.interface_frame = tk.Frame(master)
        self.interface_frame.pack(pady=10)

        self.label = tk.Label(self.interface_frame, text="Select interface:")
        self.label.grid(row=0, column=0, padx=5)

        self.interface_combobox = ttk.Combobox(self.interface_frame)
        self.interface_combobox.grid(row=0, column=1, padx=5)
        self.populate_interfaces()

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

        # Filter section
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

        # Treeview for displaying packets
        self.tree = ttk.Treeview(master, columns=(
            "No.", "Time", "Source", "Destination", "Protocol", "Length", "Src_Country", "Src_City", "Src_Time_Zone",
            "Src_Service"), show="headings")
        self.tree.heading("No.", text="No.")
        self.tree.heading("Time", text="Time")
        self.tree.heading("Source", text="Source")
        self.tree.heading("Destination", text="Destination")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Length", text="Length")
        self.tree.heading("Src_Country", text="Src Country")
        self.tree.heading("Src_City", text="Src City")
        self.tree.heading("Src_Time_Zone", text="Src Time Zone")
        self.tree.heading("Src_Service", text="Src Service")

        # Default column widths
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
        for column, width in column_widths.items():
            self.tree.column(column, width=width, anchor=tk.CENTER)

        self.tree.bind("<ButtonRelease-1>", self.display_packet_details)
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Scrollbar for Treeview
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

    def populate_interfaces(self):
        try:
            interfaces = psutil.net_if_addrs()
            interface_names = [f"{name} ({addrs[0].address})" for name, addrs in interfaces.items()]
            self.interface_combobox['values'] = interface_names
            if interface_names:
                self.interface_combobox.current(0)
        except Exception as e:
            print(f"Error populating interfaces: {e}")

    def start_filter_thread(self):
        filter_field = self.filter_field_combobox.get()
        filter_text = self.filter_entry.get()
        self.filter_thread = threading.Thread(target=self.filter_packets, args=(filter_field, filter_text))
        self.filter_thread.start()

    def filter_packets(self, filter_field, filter_text):
        self.filtered_packets = []
        for packet in self.packet_list:
            if filter_field == "Source IP":
                if hasattr(packet, 'ip') and packet.ip.src == filter_text:
                    self.filtered_packets.append(packet)
            elif filter_field == "Destination IP":
                if hasattr(packet, 'ip') and packet.ip.dst == filter_text:
                    self.filtered_packets.append(packet)
            elif filter_field == "Protocol" and hasattr(packet, 'transport_layer') and packet.transport_layer == filter_text:
                self.filtered_packets.append(packet)
        self.display_packets(self.filtered_packets)

    def display_packets(self, packets):
        self.tree.delete(*self.tree.get_children())
        for idx, packet in enumerate(packets, start=1):
            if 'ip' in packet:
                source_ip = packet.ip.src
                dest_ip = packet.ip.dst
                source_geo = IPGeolocation(source_ip)
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
            self.packet_list = []
            interface = self.interface_combobox.get().split()[0]
            self.capture_thread = threading.Thread(target=self.capture_packets, args=(interface,))
            self.capture_thread.start()
            self.running = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.continue_button.config(state=tk.DISABLED)
            self.export_button.config(state=tk.NORMAL)

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
            interface = self.interface_combobox.get().split()[0]
            self.capture_thread = threading.Thread(target=self.capture_packets, args=(interface,))
            self.capture_thread.start()
            self.running = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.continue_button.config(state=tk.DISABLED)
            self.export_button.config(state=tk.NORMAL)

    def capture_packets(self, interface):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self.capture = pyshark.LiveCapture(interface=interface)
        for packet in self.capture.sniff_continuously():
            if not self.running:
                break
            self.packet_list.append(packet)
            self.display_packet(packet)
        loop.close()

    def display_packet(self, packet):
        if 'ip' in packet:
            source_ip = packet.ip.src
            dest_ip = packet.ip.dst
            source_geo = IPGeolocation(source_ip)
            self.tree.insert("", "end", values=(
                len(self.packet_list),
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

    def open_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*.*")])
        if file_path:
            self.packet_list = []
            self.capture = pyshark.FileCapture(file_path)
            for packet in self.capture:
                self.packet_list.append(packet)
                self.display_packet(packet)

    def save_to_csv(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                                 filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(
                    ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Src_Country", "Src_City",
                     "Src_Time_Zone", "Src_Service"])
                for idx, packet in enumerate(self.packet_list, start=1):
                    if 'ip' in packet:
                        source_ip = packet.ip.src
                        dest_ip = packet.ip.dst
                        source_geo = IPGeolocation(source_ip)
                        writer.writerow([
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
                        ])
            messagebox.showinfo("Save to CSV", "Data saved successfully!")

    def export_to_csv(self):
        self.save_to_csv()

    def show_help_message(self):
        messagebox.showinfo("About", "Wireshark App\nVersion 1.0")

    def display_packet_details(self, event):
        item = self.tree.selection()
        if item:  # Kiểm tra xem có dòng nào được chọn không
            item = item[0]
            packet = self.packet_list[int(self.tree.item(item, "values")[0]) - 1]
            self.log.delete(1.0, tk.END)  # Xóa nội dung hiện tại
            self.log.insert(tk.END, str(packet))  # Hiển thị thông tin chi tiết của packet

    def show_source_country_stats(self):
        self.stats_thread = threading.Thread(target=self.generate_source_country_stats)
        self.stats_thread.start()

    def show_source_service_stats(self):
        self.stats_thread = threading.Thread(target=self.generate_source_service_stats)
        self.stats_thread.start()

    def generate_source_country_stats(self):
        src_country_count = {}

        for packet in self.packet_list:
            if 'ip' in packet:
                source_ip = packet.ip.src
                source_geo = IPGeolocation(source_ip)
                src_country = source_geo.country

                if src_country:
                    if src_country in src_country_count:
                        src_country_count[src_country] += 1
                    else:
                        src_country_count[src_country] = 1

        self.master.after(0, self.plot_pie_chart, src_country_count, "Source Country Distribution")

    def generate_source_service_stats(self):
        src_service_count = {}

        for packet in self.packet_list:
            if 'ip' in packet:
                source_ip = packet.ip.src
                source_geo = IPGeolocation(source_ip)
                src_service = source_geo.isp

                if src_service:
                    if src_service in src_service_count:
                        src_service_count[src_service] += 1
                    else:
                        src_service_count[src_service] = 1

        self.master.after(0, self.plot_pie_chart, src_service_count, "Source Service Distribution")

    def plot_pie_chart(self, data, title):
        labels = list(data.keys())
        sizes = list(data.values())
        plt.figure(figsize=(10, 6))
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
        plt.title(title)
        plt.axis('equal')
        plt.show()

    def save_to_pcap(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".pcap",
                                                 filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*.*")])
        if file_path:
            scapy_packets = []
            for packet in self.packet_list:
                if 'ip' in packet:
                    ip_packet = IP(src=packet.ip.src, dst=packet.ip.dst)
                    if 'eth' in packet:
                        ether_packet = Ether(src=packet.eth.src, dst=packet.eth.dst)
                        scapy_packets.append(ether_packet / ip_packet)
                    else:
                        scapy_packets.append(ip_packet)
            wrpcap(file_path, scapy_packets)
            messagebox.showinfo("Save to PCAP", "PCAP file saved successfully!")


def main():
    root = tk.Tk()
    app = WiresharkApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
