"""
PentestTool 
"""

import socket
import subprocess
import threading
import requests
from urllib.parse import urljoin
import json
import argparse
import sys
import re
import os

class PentestTool:
    def __init__(self):
        self.results = {}
        self.target = ""
        
    def banner(self):
        print(r"""
    ____            __    ______          __    
   / __ \___  _____/ /_  /_  __/___  ____/ /____
  / /_/ / _ \/ ___/ __/   / / / __ \/ __  / ___/
 / ____/  __(__  ) /_    / / / /_/ / /_/ (__  ) 
/_/    \___/____/\__/   /_/  \____/\__,_/____/  
                                                 
        pentesting
        """)
    
    def sanitize_filename(self, name):
        return re.sub(r'[<>:"/\\|?*]', '_', name)
    
    def port_scan(self, target, port_range="1-1000"):
        print(f"[+] Сканування портів {target} у діапазоні {port_range}...")
        if "-" in port_range:
            start_port, end_port = map(int, port_range.split("-"))
        else:
            start_port, end_port = 1, int(port_range)
        
        open_ports = []
        total_ports = end_port - start_port + 1
        current_port = 0
        
        print(f"[+] Сканування {total_ports} портів...")
        
        for port in range(start_port, end_port + 1):
            current_port += 1
            if current_port % 100 == 0:  
                print(f"    Прогрес: {current_port}/{total_ports} портів...")
                
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                    print(f"    [+] Порт {port} відкритий")
                sock.close()
            except Exception as e:
                pass
        
        print(f"[+] Сканування закынчено. Знайдено {len(open_ports)} відкритих портів")
        self.results['open_ports'] = open_ports
        self.results['port_range'] = port_range
        return open_ports
    
    def port_scan_fast(self, target):
        print(f"[+] Швидке сканування основних портів {target}...")
        
        open_ports = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 1433, 3306, 3389, 5432, 8080, 8443, 9090]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                    print(f"    [+] Порт {port} відкритий")
                sock.close()
            except:
                pass
        
        self.results['open_ports'] = open_ports
        self.results['port_range'] = "common_ports"
        return open_ports
    
    def service_detection(self, target, ports):
        if not ports:
            print("[-] Немає відкритих портів")
            return {}
            
        print("[+] Визначення ")
        
        services = {}
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 
            53: "DNS", 80: "HTTP", 110: "POP3", 443: "HTTPS",
            1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9090: "WebSM"
        }
        
        for port in ports:
            service = common_ports.get(port, "Unknown")
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((target, port))
                services[port] = service
                print(f"    [+] Порт {port}: {service}")
                sock.close()
            except:
                services[port] = service
                print(f"    [+] Порт {port}: {service}")
        
        self.results['services'] = services
        return services
    
    def web_crawler(self, target):
        print(f"[+] Сканування вебу {target}...")
        
        resources = []
        common_paths = ['/', '/admin', '/login', '/robots.txt', '/backup', '/test', '/api', '/phpmyadmin']
        
        protocols = ['http', 'https']
        
        for protocol in protocols:
            for path in common_paths:
                url = f"{protocol}://{target}{path}"
                try:
                    response = requests.get(url, timeout=3, verify=False)
                    if response.status_code < 400: 
                        resources.append(f"{url} (Status: {response.status_code})")
                        print(f"    [+] Знайдено: {url} - Status: {response.status_code}")
                except requests.exceptions.RequestException:
                    continue
        
        self.results['web_resources'] = resources
        return resources
    
    def vulnerability_scan(self, target, services):
        print("[+] Перевірка на вразливості...")
        
        vulns = []
        
        if any(port in services for port in [80, 443, 8080, 8443]):
            test_params = ["id", "page", "user", "search", "category"]
            for param in test_params:
                test_url = f"http://{target}/?{param}=1'"
                try:
                    response = requests.get(test_url, timeout=3)
                    response_lower = response.text.lower()
                    if any(error in response_lower for error in ["sql", "syntax", "mysql", "oracle", "postgresql"]):
                        vulns.append(f"Можлива SQL-ін'єкція у параметрі {param}")
                        print(f"    [!] Можлива SQL-ін'єкція в параметрі {param}")
                        break
                except:
                    pass
        
        self.results['vulnerabilities'] = vulns
        return vulns
    
    def generate_report(self):
        print("\n" + "="*50)
        print("ЗВІТ ПЕНТЕСТУ")
        print("="*50)
        
        print(f"Ціль: {self.target}")
        print(f"Діапазон портів: {self.results.get('port_range', 'Невідомо')}")
        
        if 'open_ports' in self.results:
            print(f"\nВідкриті порти ({len(self.results['open_ports'])}): {self.results['open_ports']}")
        
        if 'services' in self.results:
            print("\nСервіси знайдено:")
            for port, service in self.results['services'].items():
                print(f"   Порт {port}: {service}")
        
        if 'web_resources' in self.results and self.results['web_resources']:
            print("\nВеб:")
            for resource in self.results['web_resources']:
                print(f"   {resource}")
        
        if 'vulnerabilities' in self.results and self.results['vulnerabilities']:
            print("\nЗнайдені вразливості:")
            for vuln in self.results['vulnerabilities']:
                print(f"   {vuln}")
        else:
            print("\nВразливості не знайдено")
        
        safe_target = self.sanitize_filename(self.target)
        filename = f'report_{safe_target}.json'
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"\nЗвіт збережено у {filename}")
        except Exception as e:
            print(f"\nПомилка збереження звіту: {e}")
            filename = 'pentest_report.json'
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"Звіт збережено у {filename}")

    def extract_domain_from_url(self, url):
        if '://' in url:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.hostname or url
        return url
    
    def interactive_mode(self):
        self.banner()
        
        print("PentestTool")
        print("="*40)
        target = input("IP-адреса або домен для сканування: ").strip()
        if not target:
            target = "127.0.0.1"
            print(f"[!] Використовуються значення за замовчуванням: {target}")
        
        target = self.extract_domain_from_url(target)
        self.target = target
        
        print("\n тип сканування портів:")
        print("1. Швидке сканування (тільки основні порти)")
        print("2. Повне сканування (1-1000 портів)")
        print("3. Спеціальний діапазон портів")
        choice = input("\nВаш вибір (1-3): ").strip()
        
        if choice == "1":
            print("\n[+] Запуск швидкого сканування...")
            ports = self.port_scan_fast(target)
        elif choice == "2":
            print("\n[+] Запуск повного сканування портів 1-1000...")
            ports = self.port_scan(target, "1-1000")
        elif choice == "3":
            port_range = input("Введіть діапазон портів (наприклад, 1-1000 або 80-443): ").strip()
            if not port_range:
                port_range = "1-1000"
            print(f"\n[+] Запуск сканування портів {port_range}...")
            ports = self.port_scan(target, port_range)
        else:
            print("[!] Неправильний вибір. Запускаю швидке сканування...")
            ports = self.port_scan_fast(target)
        
        if ports:
            services = self.service_detection(target, ports)
            self.web_crawler(target)
            self.vulnerability_scan(target, services)
        else:
            print("[-] Відкритих портів немає")
        
        self.generate_report()

def main():
    import warnings
    warnings.filterwarnings("ignore", message="Unverified HTTPS request")
    
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description='PentestTool v0.2')
        parser.add_argument('target', help='IP-адреса або домен')
        parser.add_argument('-p', '--ports', help='Діапазон портів для сканування (наприклад, 1-199)', default='1-1000')
        parser.add_argument('-f', '--fast', action='store_true', help='Швидке сканування тільки основних портів')
        args = parser.parse_args()
        
        tool = PentestTool()
        tool.target = tool.extract_domain_from_url(args.target)
        
        if args.fast:
            tool.port_scan_fast(tool.target)
        else:
            tool.port_scan(tool.target, args.ports)
        
        if tool.results.get('open_ports'):
            services = tool.service_detection(tool.target, tool.results['open_ports'])
            tool.web_crawler(tool.target)
            tool.vulnerability_scan(tool.target, services)
        
        tool.generate_report()
    else:
        tool = PentestTool()
        tool.interactive_mode()

if __name__ == "__main__":
    main()
