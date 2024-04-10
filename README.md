# CodeAlpha_BasicNetworkSniffer

This Python script allows you to sniff packets on a network interface of your choice. It utilizes the `scapy` library for packet manipulation and analysis.

# Features
=> Displays information about captured packets, including Ethernet frames, IP packets, and transport layer (TCP/UDP).
=> Supports selection of a network interface from the available options.
=> Provides color-coded output for easy visualization of different packet components.

# Requirements
=> Python
=> `scapy` library
=> `netifaces` library

# Installation
1. Install Python from [Python's official website](https://www.python.org/downloads/).
2. Install required Python libraries using pip:
   ```
   pip install scapy
   pip install netifaces
   ```

# Usage
1. Run the script in a terminal or command prompt:
   ```
   python PacketSniffer.py
   ```
2. Follow the on-screen instructions to select a network interface for packet sniffing.

# Notes
=> Ensure that you have appropriate permissions to access network interfaces, especially on Windows and macOS.
=> Make sure any firewall or security software allows the script to capture network traffic.
