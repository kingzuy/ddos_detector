import time
import logging
import threading
from collections import defaultdict
from datetime import datetime, timedelta
from threading import Timer
import os
from scapy.all import *
import colorama
from colorama import Fore, Back, Style

# Inisialisasi colorama
colorama.init()

class ConsoleLogger:
    @staticmethod
    def alert(message):
        """Tampilkan pesan alert dengan warna merah"""
        print(f"{Fore.RED}{Back.BLACK}[ALERT] {message}{Style.RESET_ALL}")
    
    @staticmethod
    def info(message):
        """Tampilkan pesan info dengan warna biru"""
        print(f"{Fore.BLUE}[INFO] {message}{Style.RESET_ALL}")
    
    @staticmethod
    def success(message):
        """Tampilkan pesan sukses dengan warna hijau"""
        print(f"{Fore.GREEN}[SUCCESS] {message}{Style.RESET_ALL}")

class DDoSDetector:
    def __init__(self):
        self.running = True
        # Inisialisasi parameter
        self.THRESHOLD_CONNECTIONS = 1000
        self.THRESHOLD_PACKETS = 5000
        self.THRESHOLD_BANDWIDTH = 10000000
        self.TIME_WINDOW = 60
        self.BLOCK_DURATION = 300  # 5 menit dalam detik
        
        # Tracking data
        self.ip_connections = defaultdict(int)
        self.packet_count = defaultdict(int)
        self.bandwidth_usage = defaultdict(int)
        self.blacklist = set()
        self.whitelist = set()
        self.attack_history = []
        self.blocked_ips = {}  # Untuk menyimpan waktu pemblokiran IP
        
        # Logger
        self.console = ConsoleLogger()
        
        # Setup logging file
        logging.basicConfig(
            filename='ddos_detection.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
        self.start_monitoring()

    def log_attack(self, ip, reason, src_port, dst_port):
        """Mencatat serangan ke dalam history"""
        timestamp = datetime.now()
        attack_info = {
            'timestamp': timestamp,
            'ip': ip,
            'reason': reason,
            'src_port': src_port,
            'dst_port': dst_port
        }
        self.attack_history.append(attack_info)
        
        # Format pesan alert
        time_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
        alert_message = f"Time: {time_str} | Attack from IP: {ip} | Reason: {reason} | Source Port: {src_port} | Destination Port: {dst_port}"
        
        # Tampilkan di console dengan warna merah
        self.console.alert(alert_message)

    def monitor_network(self):
        """Monitoring lalu lintas jaringan"""
        def packet_callback(packet):
            if IP in packet:
                src_ip = packet[IP].src
                src_port = packet.sport if TCP in packet or UDP in packet else None
                dst_ip = packet[IP].dst
                dst_port = packet.dport if TCP in packet or UDP in packet else None
                
                if src_ip in self.whitelist:
                    return
                
                if src_ip in self.blacklist:
                    self.block_ip(src_ip)
                    return
                
                # Update statistik
                self.packet_count[src_ip] += 1
                self.bandwidth_usage[src_ip] += len(packet)
                self.ip_connections[src_ip] += 1
                
                # Cek anomali
                self.check_anomalies(src_ip, src_port, dst_port)
        
        self.console.info("Starting network monitoring...")
        sniff(prn=packet_callback, store=0)

    def check_anomalies(self, ip, src_port, dst_port):
        """Deteksi anomali berdasarkan threshold"""
        if ip in self.blocked_ips:
            return  # Jika IP sudah diblokir, abaikan

        if self.ip_connections[ip] > self.THRESHOLD_CONNECTIONS:
            self.detect_ddos(ip, "Too many connections", src_port, dst_port)
            
        if self.packet_count[ip] > self.THRESHOLD_PACKETS:
            self.detect_ddos(ip, "Too many packets", src_port, dst_port)
            
        if self.bandwidth_usage[ip] > self.THRESHOLD_BANDWIDTH:
            self.detect_ddos(ip, "Excessive bandwidth usage", src_port, dst_port)

    def detect_ddos(self, ip, reason, src_port, dst_port):
        """Handle deteksi DDoS"""
        self.log_attack(ip, reason, src_port, dst_port)
        self.blacklist.add(ip)
        self.block_ip(ip)
        self.alert_admin(ip, reason)

    def block_ip(self, ip):
        """Implementasi pemblokiran IP selama 5 menit"""
        try:
            if ip not in self.blocked_ips:
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                self.blocked_ips[ip] = datetime.now()
                self.console.success(f"Successfully blocked IP: {ip} for 5 minutes")
                
                # Set timer untuk membuka blokir setelah 5 menit
                Timer(self.BLOCK_DURATION, self.unblock_ip, args=[ip]).start()
            else:
                self.console.info(f"IP {ip} is already blocked")
        except Exception as e:
            self.console.alert(f"Failed to block IP {ip}: {e}")

    def unblock_ip(self, ip):
        """Membuka blokir IP setelah 5 menit"""
        try:
            os.system(f"iptables -D INPUT -s {ip} -j DROP")
            del self.blocked_ips[ip]
            self.console.info(f"Unblocked IP: {ip}")
        except Exception as e:
            self.console.alert(f"Failed to unblock IP {ip}: {e}")

    def display_attack_history(self):
        """Tampilkan history serangan"""
        print("\n=== Attack History ===")
        for attack in self.attack_history:
            time_str = attack['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            self.console.alert(
                f"Time: {time_str} | IP: {attack['ip']} | Reason: {attack['reason']} | Source Port: {attack['src_port']} | Destination Port: {attack['dst_port']}"
            )

    def display_blocked_ips(self):
        """Tampilkan IP yang sedang diblokir"""
        if self.blocked_ips:
            print("\n=== Currently Blocked IPs ===")
            for ip, block_time in self.blocked_ips.items():
                remaining_time = timedelta(seconds=self.BLOCK_DURATION) - (datetime.now() - block_time)
                self.console.info(f"IP: {ip} | Remaining block time: {remaining_time}")

    def start_monitoring(self):
        """Memulai thread monitoring"""
        threading.Thread(target=self.monitor_network, daemon=True).start()
        threading.Thread(target=self.clean_old_data, daemon=True).start()
        threading.Thread(target=self.display_stats, daemon=True).start()

    def clean_old_data(self):
        """Membersihkan data lama secara periodik"""
        while self.running:
            time.sleep(self.TIME_WINDOW)
            self.ip_connections.clear()
            self.packet_count.clear()
            self.bandwidth_usage.clear()

    def display_stats(self):
        """Tampilkan statistik secara periodik"""
        while self.running:
            time.sleep(5)
            stats = self.get_statistics()
            print("\n=== Current Statistics ===")
            for key, value in stats.items():
                self.console.info(f"{key}: {value}")
            self.display_blocked_ips()

    def get_statistics(self):
        """Dapatkan statistik monitoring"""
        return {
            "Total Connections": sum(self.ip_connections.values()),
            "Total Packets": sum(self.packet_count.values()),
            "Total Bandwidth (bytes)": sum(self.bandwidth_usage.values()),
            "Blacklisted IPs": len(self.blacklist),
            "Whitelisted IPs": len(self.whitelist),
            "Total Attacks Detected": len(self.attack_history),
            "Currently Blocked IPs": len(self.blocked_ips)
        }

    def alert_admin(self, ip, reason):
        """Mengirim alert ke admin"""
        message = f"DDoS attack detected from IP {ip}. Reason: {reason}"
        logging.warning(message)
        # Di sini Anda bisa menambahkan kode untuk mengirim notifikasi ke admin
        # misalnya melalui email, SMS, atau sistem notifikasi lainnya

def main():
    print(f"{Fore.CYAN}=== DDoS Detection System ===={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Press Ctrl+C to exit{Style.RESET_ALL}\n")
    
    detector = DDoSDetector()
    
    while True:
        try:
            time.sleep(5)  # Tampilkan setiap 5 detik
            detector.display_blocked_ips()
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Do you want to stop the DDoS detection system? (Y/n){Style.RESET_ALL}")
            choice = input().lower()
            
            if choice == 'y' or choice == '':
                print(f"\n{Fore.YELLOW}Shutting down DDoS detection system...{Style.RESET_ALL}")
                detector.display_attack_history()
                detector.running = False  # Set running to False to stop threads
                break
            else:
                print(f"\n{Fore.GREEN}Continuing DDoS detection...{Style.RESET_ALL}")
                continue

if __name__ == "__main__":
    main()