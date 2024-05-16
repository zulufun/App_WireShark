import tkinter as tk
from tkinter import scrolledtext
import pyshark
import threading

class WiresharkApp:
    def __init__(self, master):
        self.master = master
        master.title("Wireshark App")

        self.label = tk.Label(master, text="Enter interface name:")
        self.label.pack()

        self.interface_entry = tk.Entry(master)
        self.interface_entry.pack()

        self.start_button = tk.Button(master, text="Start", command=self.start_capture)
        self.start_button.pack()

        self.stop_button = tk.Button(master, text="Stop", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.pack()

        self.log = scrolledtext.ScrolledText(master, width=60, height=20)
        self.log.pack()

        self.capture = None
        self.capture_thread = None
        self.running = False

    def start_capture(self):
        if not self.running:
            interface = self.interface_entry.get()
            try:
                self.capture = pyshark.LiveCapture(interface=interface)
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

    def capture_packets(self):
        for packet in self.capture.sniff_continuously():
            if not self.running:
                break
            self.log.insert(tk.END, "{}\n".format(packet))

def main():
    root = tk.Tk()
    app = WiresharkApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
