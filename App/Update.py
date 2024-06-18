import tkinter as tk
from tkinter import scrolledtext, filedialog, ttk, messagebox
import pyshark
import threading
import csv
import requests
import matplotlib.pyplot as plt
import asyncio
import psutil  # Thêm thư viện psutil

class IPGeolocation:
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
        try:
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
        except requests.RequestException as e:
            print(f"Error fetching geolocation data: {e}")

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
        self.file_menu.add_command(label="Stats", command=self.show_stats)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=master.quit)

        self.help_menu = tk.Menu(self.menu, tearoff=False)
        self.menu.add_cascade(label="Help", menu=self.help_menu)
        self.help_menu.add_command(label="About", command=self.show_help_message)

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
        selected_item = self.tree.selection()[0]
        packet_details = self.tree.item(selected_item, 'values')
        self.log.insert(tk.END, f"Packet Details:\n{packet_details}\n")

    def show_stats(self):
        self.stats_thread = threading.Thread(target=self.generate_stats)
        self.stats_thread.start()

    def generate_stats(self):
        src_country_count = {}
        src_service_count = {}

        for packet in self.packet_list:
            if 'ip' in packet:
                source_ip = packet.ip.src
                source_geo = IPGeolocation(source_ip)
                src_country = source_geo.country
                src_service = source_geo.isp

                if src_country:
                    if src_country in src_country_count:
                        src_country_count[src_country] += 1
                    else:
                        src_country_count[src_country] = 1

                if src_service:
                    if src_service in src_service_count:
                        src_service_count[src_service] += 1
                    else:
                        src_service_count[src_service] = 1

        self.plot_pie_chart(src_country_count, "Source Country Distribution")
        self.plot_pie_chart(src_service_count, "Source Service Distribution")

    def plot_pie_chart(self, data, title):
        labels = list(data.keys())
        sizes = list(data.values())
        plt.figure(figsize=(10, 6))
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
        plt.title(title)
        plt.axis('equal')
        plt.show()

if __name__ == "__main__":
    root = tk.Tk()
    app = WiresharkApp(root)
    root.mainloop()
