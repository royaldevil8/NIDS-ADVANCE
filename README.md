# 🛡 Network Intrusion Detection System (NIDS) using Scapy & Machine Learning

## 📌 Overview

This project is a real-time **Network Intrusion Detection System (NIDS)** designed to monitor live network traffic, analyze packet behavior, and detect potential cyber threats using a combination of **rule-based detection** and **machine learning**.

Unlike basic sniffers, this system provides **intelligent threat detection, automated response, and visual analytics**, making it suitable for cybersecurity learning, research, and internship-level demonstrations.

---

## 🚀 Key Features

### 🔍 Real-Time Packet Monitoring

* Captures live network traffic using **Scapy**
* Processes packets instantly for threat analysis

### 🧠 Hybrid Detection Engine

* Rule-based detection:

  * Port Scanning
  * SYN Flood
  * ICMP Flood
* Machine Learning-based classification with confidence score

### 🤖 Machine Learning Integration

* Uses **Random Forest model**
* Dynamic model loading & prediction
* Auto-retraining system based on new data

### 🌍 GeoIP Tracking

* Detects country of IP addresses
* Differentiates between **local and public traffic**

### 🚫 Automated Threat Response

* Auto IP blocking using firewall rules
* Blacklist management system
* Auto-unblock after timeout

### 📊 Interactive GUI Dashboard

* Real-time packet visualization
* Attack highlighting & severity levels
* Filters (Protocol, Traffic Type, Status)
* Graphs:

  * Attack distribution
  * Country-wise traffic
  * Traffic rate timeline
  * Top attackers

### 📢 Alert System

* Email alerts
* Telegram alerts
* Sound + popup notifications

### 📁 Data Export

* Export captured packets as **PCAP files**

---

## 🏗 Architecture

Sniffer (Scapy) → Detection Engine → ML Model → Queue → GUI Dashboard

---

## 🧪 Technologies Used

* Python
* Scapy
* Scikit-learn
* Tkinter (GUI)
* Matplotlib (Visualization)
* GeoIP2
* iptables (Linux firewall)

---

## ⚙️ How It Works

1. Captures packets in real time
2. Extracts behavioral features
3. Applies rule-based + ML detection
4. Flags suspicious traffic
5. Displays results in GUI
6. Triggers alerts or blocks malicious IPs

---

## ⚠️ Limitations

* Requires root privileges for packet sniffing & blocking
* Basic ML model (can be enhanced with advanced datasets)
* Optimized for small to medium traffic environments

---

## 🔮 Future Improvements

* Deep packet inspection (DPI)
* Advanced ML models (XGBoost / LSTM)
* Web-based dashboard (Flask/React)
* Cloud deployment & scaling
* Global attack visualization (world map)

---

## 🎯 Use Cases

* Cybersecurity learning & research
* Intrusion detection simulation
* Network monitoring tool
* Internship / academic project

---

## 👨‍💻 Author

Developed as a cybersecurity project focusing on **real-time network threat detection and analysis**.
