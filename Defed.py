import os
import pyshark
import scapy.all as scapy
import tkinter as tk
from tkinter import filedialog, messagebox
import csv
import xml.etree.ElementTree as ET

def merge_pcaps(input_files, output_file):
    """Merge selected PCAP files into a single PCAP file."""
    packets = []
    for file in input_files:
        if file.lower().endswith('.pcap') or file.lower().endswith('.pcapng'):
            packets.extend(scapy.rdpcap(file))
    scapy.wrpcap(output_file, packets)

def convert_pcap_to_csv(pcap_file, csv_file):
    """Convert a PCAP file to CSV format."""
    cap = pyshark.FileCapture(pcap_file)
    with open(csv_file, mode='w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        # Write header
        csv_writer.writerow(["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"])
        for packet in cap:
            try:
                csv_writer.writerow([
                    getattr(packet, 'number', 'N/A'),
                    getattr(packet, 'sniff_time', 'N/A'),
                    packet.get('ip.src', 'N/A') if 'ip.src' in packet else 'N/A',
                    packet.get('ip.dst', 'N/A') if 'ip.dst' in packet else 'N/A',
                    packet.highest_layer if hasattr(packet, 'highest_layer') else 'N/A',
                    packet.length if hasattr(packet, 'length') else 'N/A',
                    getattr(packet, 'info', 'N/A') if hasattr(packet, 'info') else 'N/A'
                ])
            except Exception as e:
                print(f"Error processing packet: {e}")
    cap.close()

def convert_pcap_to_netxml(pcap_file, netxml_file):
    """Convert a PCAP file to Kismet .netxml format."""
    cap = pyshark.FileCapture(pcap_file)
    root = ET.Element("detection-run")

    for packet in cap:
        try:
            if hasattr(packet, 'wlan'):  # Check if the packet has WLAN data
                network = ET.SubElement(root, "wireless-network", {
                    "type": "infrastructure",
                    "first-time": str(packet.sniff_time),
                    "last-time": str(packet.sniff_time)
                })

                ssid_tag = ET.SubElement(network, "SSID")
                ssid = packet.wlan.get("wlan.ssid", "Unknown")
                ET.SubElement(ssid_tag, "essid").text = ssid

                bssid = packet.wlan.get("wlan.bssid", "Unknown")
                ET.SubElement(network, "BSSID").text = bssid

                channel = packet.wlan.get("wlan_radio.channel", "Unknown")
                ET.SubElement(network, "channel").text = channel

                encryption = ET.SubElement(network, "encryption")
                ET.SubElement(encryption, "type").text = "WEP" if "wep" in packet.layers else "Unknown"

        except Exception as e:
            print(f"Error processing packet for netxml: {e}")

    cap.close()

    # Write to file
    tree = ET.ElementTree(root)
    tree.write(netxml_file, encoding='utf-8', xml_declaration=True)

def main():
    """Main function to handle the user interface."""
    def merge_action():
        files_selected = filedialog.askopenfilenames(filetypes=[("PCAP Files", "*.pcap;*.pcapng")], title="Select PCAP Files to Merge")
        if not files_selected:
            return
        output_file = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP Files", "*.pcap")])
        if not output_file:
            return
        merge_pcaps(files_selected, output_file)
        messagebox.showinfo("Success", f"Selected PCAP files merged into {output_file}")

    def convert_to_csv_action():
        pcap_files = filedialog.askopenfilenames(filetypes=[("PCAP Files", "*.pcap;*.pcapng")], title="Select PCAP Files to Convert")
        if not pcap_files:
            return
        for pcap_file in pcap_files:
            csv_file = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")], initialfile=os.path.splitext(os.path.basename(pcap_file))[0] + ".csv")
            if not csv_file:
                continue
            convert_pcap_to_csv(pcap_file, csv_file)
        messagebox.showinfo("Success", "Selected PCAP files converted to CSV")

    def convert_to_netxml_action():
        pcap_files = filedialog.askopenfilenames(filetypes=[("PCAP Files", "*.pcap;*.pcapng")], title="Select PCAP Files to Convert")
        if not pcap_files:
            return
        for pcap_file in pcap_files:
            netxml_file = filedialog.asksaveasfilename(defaultextension=".netxml", filetypes=[("NetXML Files", "*.netxml")], initialfile=os.path.splitext(os.path.basename(pcap_file))[0] + ".netxml")
            if not netxml_file:
                continue
            convert_pcap_to_netxml(pcap_file, netxml_file)
        messagebox.showinfo("Success", "Selected PCAP files converted to NetXML")

    # Create the main window
    root = tk.Tk()
    root.title("PCAP Fuser & Converter")
    root.geometry("400x300")
    root.configure(bg="#f0f8ff")

    header_label = tk.Label(root, text="PCAP Fuser & Converter", font=("Helvetica", 16, "bold"), bg="#f0f8ff")
    header_label.pack(pady=10)

    merge_button = tk.Button(root, text="Merge PCAP Files", command=merge_action, font=("Helvetica", 12), bg="#007acc", fg="white", relief="raised", bd=3)
    merge_button.pack(pady=10, ipadx=10, ipady=5)

    convert_csv_button = tk.Button(root, text="Convert PCAP to CSV", command=convert_to_csv_action, font=("Helvetica", 12), bg="#007acc", fg="white", relief="raised", bd=3)
    convert_csv_button.pack(pady=10, ipadx=10, ipady=5)

    convert_netxml_button = tk.Button(root, text="Convert PCAP to NetXML", command=convert_to_netxml_action, font=("Helvetica", 12), bg="#007acc", fg="white", relief="raised", bd=3)
    convert_netxml_button.pack(pady=10, ipadx=10, ipady=5)

    footer_label = tk.Label(root, text="Made with ❤️ for network analysis", font=("Helvetica", 10), bg="#f0f8ff")
    footer_label.pack(pady=10)

    powered_label = tk.Label(root, text="Powered by Danybit", font=("Helvetica", 8, "italic"), bg="#f0f8ff", anchor="e")
    powered_label.pack(side="bottom", anchor="se", padx=10, pady=5)

    root.mainloop()

if __name__ == "__main__":
    main()
