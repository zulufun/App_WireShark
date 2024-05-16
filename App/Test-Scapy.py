import tkinter as tk
from tkinter import scrolledtext, filedialog, ttk
from scapy.all import *
import threading
import csv
import requests


class IPGeolocation:
    def __init__(self, ip_address):
        self.latitude = ''
        self.longitude = ''
        self.country = ''
        self.city = ''
        self.time_zone = ''
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


class WiresharkApp:
    def __init__(self, master):
        self.master = master
        master.title("Wireshark App")

        self.input_frame = tk.Frame(master)
        self.input_frame.pack(pady=10)

        self.label = tk.Label(self.input_frame, text="Enter interface name:")
        self.label.grid(row=0, column=0, padx=5)

        self.interface_entry = tk.Entry(self.input_frame)
        self.interface_entry.grid(row=0, column=1, padx=5)

        self.start_button = tk.Button(self.input_frame, text="Start", command=self.start_capture)
        self.start_button.grid(row=0, column=2, padx=5)

        self.stop_button = tk.Button(self.input_frame, text="Stop", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=3, padx=5)

        self.tree = ttk.Treeview(master, columns=(
        "Time", "Source", "Destination", "Src_Country", "Src_City", "Src_Time_Zone"), show="headings")

        self.tree.heading("Time", text="Time")
        self.tree.heading("Source", text="Source")
        self.tree.heading("Destination", text="Destination")
        self.tree.heading("Src_Country", text="Src_Country")
        self.tree.heading("Src_City", text="Src_City")
        self.tree.heading("Src_Time_Zone", text="Src_Time Zone")

        self.tree.bind("<ButtonRelease-1>", self.display_packet_details)
        self.tree.pack(fill=tk.BOTH, expand=True)

        self.scrollbar = ttk.Scrollbar(master, orient="vertical", command=self.tree.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=self.scrollbar.set)

        self.log = scrolledtext.ScrolledText(master, width=60, height=10)
        self.log.pack(fill=tk.BOTH, expand=True)

        self.capture = None
        self.capture_thread = None
        self.running = False
        self.packet_list = []

    def start_capture(self):
        if not self.running:
            interface = self.interface_entry.get()
            try:
                self.capture = sniff(iface=interface, prn=self.capture_packets, store=False)
                self.log.insert(tk.END, "Started capturing on interface: {}\n".format(interface))
                self.start_button.config(state=tk.DISABLED)
                self.stop_button.config(state=tk.NORMAL)
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

    def capture_packets(self, packet):
        if 'IP' in packet:
            source_ip = packet[IP].src
            dest_ip = packet[IP].dst
            source_geo = IPGeolocation(source_ip)
            dest_geo = IPGeolocation(dest_ip)
            self.packet_list.append(packet)
            self.tree.insert("", "end", values=(
                packet.time,
                source_ip,
                dest_ip,
                source_geo.country,
                source_geo.city,
                source_geo.time_zone
            ))

    def display_packet_details(self, event):
        item = self.tree.selection()
        if item:
            item = item[0]
            packet = self.packet_list[int(self.tree.item(item, "values")[0]) - 1]
            self.log.delete(1.0, tk.END)
            self.log.insert(tk.END, str(packet))


def main():
    root = tk.Tk()
    app = WiresharkApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
