import tkinter as tk
from tkinter import scrolledtext, filedialog, ttk
import pyshark
import threading
import csv

class WiresharkApp:
    def __init__(self, master):
        self.master = master
        master.title("Wireshark App")

        # Khởi tạo Frame chứa phần nhập liệu và nút bắt đầu
        self.input_frame = tk.Frame(master)
        self.input_frame.pack(pady=10)

        # Label và Entry để nhập tên interface
        self.label = tk.Label(self.input_frame, text="Enter interface name:")
        self.label.grid(row=0, column=0, padx=5)
        self.interface_entry = tk.Entry(self.input_frame)
        self.interface_entry.grid(row=0, column=1, padx=5)

        # Nút bắt đầu và dừng
        self.start_button = tk.Button(self.input_frame, text="Start", command=self.start_capture)
        self.start_button.grid(row=0, column=2, padx=5)
        self.stop_button = tk.Button(self.input_frame, text="Stop", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=3, padx=5)
        self.export_button = tk.Button(self.input_frame, text="Export to CSV", command=self.export_to_csv, state=tk.DISABLED)
        self.export_button.grid(row=0, column=4, padx=5)

        # Treeview để hiển thị các gói tin
        self.tree = ttk.Treeview(master, columns=("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"), show="headings")
        self.tree.heading("No.", text="No.")
        self.tree.heading("Time", text="Time")
        self.tree.heading("Source", text="Source")
        self.tree.heading("Destination", text="Destination")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Length", text="Length")
        self.tree.heading("Info", text="Info")
        self.tree.bind("<ButtonRelease-1>", self.display_packet_details)  # Bắt sự kiện click chuột
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Scrollbar cho Treeview
        self.scrollbar = ttk.Scrollbar(master, orient="vertical", command=self.tree.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=self.scrollbar.set)

        # Log ScrolledText widget
        self.log = scrolledtext.ScrolledText(master, width=60, height=10)
        self.log.pack(fill=tk.BOTH, expand=True)

        # Biến để lưu trạng thái của capture
        self.capture = None
        self.capture_thread = None
        self.running = False
        self.packet_list = []

    def start_capture(self):
        # Bắt đầu capture khi nhấn nút Start
        if not self.running:
            interface = self.interface_entry.get()
            try:
                # Khởi tạo capture mới
                self.capture = pyshark.LiveCapture(interface=interface)
                self.log.insert(tk.END, "Started capturing on interface: {}\n".format(interface))

                # Disable nút bắt đầu, kích hoạt nút dừng và export
                self.start_button.config(state=tk.DISABLED)
                self.stop_button.config(state=tk.NORMAL)
                self.export_button.config(state=tk.DISABLED)

                # Bắt đầu capture ở một thread mới
                self.running = True
                self.capture_thread = threading.Thread(target=self.capture_packets)
                self.capture_thread.start()
            except Exception as e:
                self.log.insert(tk.END, "Error: {}\n".format(e))

    def stop_capture(self):
        # Dừng capture khi nhấn nút Dừng
        if self.running:
            self.running = False
            if self.capture:
                self.capture.close()
            self.log.insert(tk.END, "Capture stopped\n")

            # Kích hoạt nút bắt đầu, vô hiệu hóa nút dừng và export
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.export_button.config(state=tk.NORMAL)

    def capture_packets(self):
        # Hàm để capture gói tin
        for idx, packet in enumerate(self.capture.sniff_continuously(), start=1):
            if not self.running:
                break
            self.packet_list.append(packet)
# Fix bug 19/4/2024 - Bug (No attribute named ip)
            # Kiểm tra xem gói tin có phải là IP hay không
            if 'IP' in packet:
                src_ip = packet['IP'].src
                dst_ip = packet['IP'].dst
            else:
                src_ip = "N/A"
                dst_ip = "N/A"

            # Thêm thông tin vào Treeview
            self.tree.insert("", "end", values=(
            idx, packet.sniff_time, src_ip, dst_ip, packet.transport_layer, packet.length, packet.layers[1].layer_name))

    def display_packet_details(self, event):
        # Hiển thị thông tin chi tiết của gói tin khi click vào Treeview
        item = self.tree.selection()
        if item:  # Kiểm tra xem có dòng nào được chọn không
            item = item[0]
            packet = self.packet_list[int(self.tree.item(item, "values")[0]) - 1]
            self.log.delete(1.0, tk.END)  # Xóa nội dung hiện tại
            self.log.insert(tk.END, str(packet))  # Hiển thị thông tin chi tiết của packet

    def export_to_csv(self):
        # Xuất dữ liệu gói tin ra file CSV
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if file_path:
            try:
                with open(file_path, mode='w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"])
                    for idx, packet in enumerate(self.packet_list, start=1):
                        writer.writerow([idx, packet.sniff_time, packet.ip.src, packet.ip.dst, packet.transport_layer, packet.length, packet.layers[1].layer_name])
                self.log.insert(tk.END, "Data exported to {}\n".format(file_path))
            except Exception as e:
                self.log.insert(tk.END, "Error exporting to CSV: {}\n".format(e))

def main():
    root = tk.Tk()
    app = WiresharkApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
