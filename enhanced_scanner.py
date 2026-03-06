#!/usr/bin/env python3
"""
Enhanced Network Scanner для Android/Termux
Легально получает MAC-адреса БЕЗ root через множественные методы
"""

import socket
import subprocess
import re
import platform
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import time

class EnhancedNetworkScanner:
    def __init__(self, interface=None, timeout=1, threads=50):
        self.interface = interface
        self.timeout = timeout
        self.threads = threads
        self.results = []
        self.os_type = platform.system().lower()
        self.is_termux = os.path.exists('/data/data/com.termux')
        
    def get_local_ip(self):
        """Получить локальный IP адрес"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            cidr = self.get_cidr_for_ip(ip)
            return ip, cidr
        except:
            return None, None
    
    def get_cidr_for_ip(self, ip):
        """Определить маску подсети"""
        try:
            result = subprocess.run(['ip', 'addr'], 
                                  capture_output=True, text=True, timeout=2)
            pattern = rf'inet {re.escape(ip)}/(\d+)'
            match = re.search(pattern, result.stdout)
            if match:
                return match.group(1)
        except:
            pass
        return '24'
    
    def get_mac_vendor(self, mac):
        """Расширенная база производителей"""
        vendors = {
            # VMware/VirtualBox
            '00:50:56': 'VMware', '08:00:27': 'VirtualBox', '52:54:00': 'QEMU/KVM',
            '00:0C:29': 'VMware', '00:15:5D': 'Microsoft/Hyper-V',
            
            # Apple
            '00:1B:63': 'Apple', '00:25:00': 'Apple', 'F0:18:98': 'Apple',
            'A4:83:E7': 'Apple', '3C:15:C2': 'Apple', '00:3A:99': 'Apple',
            '00:D0:02': 'Apple', 'AC:DE:48': 'Apple',
            
            # Raspberry Pi
            'DC:A6:32': 'Raspberry Pi', 'B8:27:EB': 'Raspberry Pi',
            'E4:5F:01': 'Raspberry Pi',
            
            # Cisco
            '78:CA:39': 'Cisco', '00:1A:A1': 'Cisco', '00:12:43': 'Cisco',
            
            # TP-Link
            'D8:0D:17': 'TP-Link', 'EC:08:6B': 'TP-Link', '50:C7:BF': 'TP-Link',
            
            # D-Link
            '28:6A:BA': 'D-Link', '00:17:9A': 'D-Link',
            
            # Samsung
            '18:B9:05': 'Samsung', '30:07:4D': 'Samsung', '00:12:FB': 'Samsung',
            '34:23:BA': 'Samsung', 'E8:50:8B': 'Samsung',
            
            # Xiaomi
            '20:E5:2A': 'XIAOMI', '64:09:80': 'XIAOMI', '34:CE:00': 'XIAOMI',
            'F8:A4:5F': 'XIAOMI', '64:B4:73': 'XIAOMI',
            
            # OPPO/OnePlus
            '22:D9:27': 'OPPO', 'E8:9F:80': 'OnePlus', '68:3E:34': 'OnePlus',
            
            # Huawei/Honor
            '00:E0:FC': 'Huawei', '48:DB:50': 'Huawei', 'B4:30:52': 'Huawei',
            
            # Google
            'DA:A1:19': 'Google', '3C:5A:B4': 'Google',
            
            # Amazon
            '00:FC:8B': 'Amazon', '84:D6:D0': 'Amazon',
            
            # Dell
            '00:1A:A0': 'Dell', 'D0:67:E5': 'Dell',
            
            # HP
            '00:1F:29': 'HP', '3C:D9:2B': 'HP',
            
            # Asus
            '00:1F:C6': 'ASUS', '08:60:6E': 'ASUS',
        }
        
        if not mac:
            return 'Unknown'
        
        # Проверка по OUI (первые 3 байта)
        prefix = mac[:8].upper()
        return vendors.get(prefix, 'Unknown')
    
    def get_mac_via_ip_neigh(self, ip):
        """Метод 1: ip neigh show (работает БЕЗ root на некоторых Android)"""
        try:
            result = subprocess.run(['ip', 'neigh', 'show', ip], 
                                  capture_output=True, text=True, timeout=2)
            if 'lladdr' in result.stdout:
                mac_match = re.search(r'([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', result.stdout)
                if mac_match:
                    return mac_match.group(0).upper()
        except:
            pass
        return None
    
    def get_mac_via_proc_net_arp(self, ip):
        """Метод 2: Чтение /proc/net/arp (может не работать без root)"""
        try:
            with open('/proc/net/arp', 'r') as f:
                lines = f.readlines()
                for line in lines:
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            mac = parts[3]
                            if mac != '00:00:00:00:00:00':
                                return mac.upper()
        except:
            pass
        return None
    
    def get_mac_via_arp_command(self, ip):
        """Метод 3: Команда arp (классический метод)"""
        try:
            result = subprocess.run(['arp', ip], 
                                  capture_output=True, text=True, timeout=2)
            mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', result.stdout)
            if mac_match:
                return mac_match.group(0).replace('-', ':').upper()
        except:
            pass
        return None
    
    def get_mac_via_getent(self, ip):
        """Метод 4: getent для некоторых систем"""
        try:
            result = subprocess.run(['getent', 'ethers', ip], 
                                  capture_output=True, text=True, timeout=2)
            mac_match = re.search(r'([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', result.stdout)
            if mac_match:
                return mac_match.group(0).upper()
        except:
            pass
        return None
    
    def get_mac_via_mdns(self, ip):
        """Метод 5: Попытка через mDNS broadcast (пассивный)"""
        # Этот метод требует прослушивания mDNS трафика
        # Реализация упрощена, полная версия требует socket programming
        return None
    
    def get_hostname_methods(self, ip):
        """Множественные методы получения hostname"""
        methods = []
        
        # Метод 1: socket.gethostbyaddr
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            if hostname and hostname != ip:
                methods.append(('DNS', hostname))
        except:
            pass
        
        # Метод 2: nslookup (если доступен)
        try:
            result = subprocess.run(['nslookup', ip], 
                                  capture_output=True, text=True, timeout=2)
            name_match = re.search(r'name = (.+?)\.', result.stdout)
            if name_match:
                methods.append(('nslookup', name_match.group(1)))
        except:
            pass
        
        # Метод 3: nmblookup для Windows устройств (если доступен)
        try:
            result = subprocess.run(['nmblookup', '-A', ip], 
                                  capture_output=True, text=True, timeout=2)
            # Парсинг NetBIOS имени
            for line in result.stdout.split('\n'):
                if '<00>' in line:
                    name = line.split()[0].strip()
                    if name:
                        methods.append(('NetBIOS', name))
                        break
        except:
            pass
        
        return methods[0][1] if methods else None
    
    def get_mac_address(self, ip):
        """
        Главный метод получения MAC - пробует ВСЕ доступные методы
        Cascade fallback для максимальной совместимости
        """
        # Предварительный ping для заполнения ARP cache
        try:
            subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                         capture_output=True, timeout=2)
        except:
            pass
        
        # Пробуем все методы по очереди
        methods = [
            ('ip neigh', self.get_mac_via_ip_neigh),
            ('proc/net/arp', self.get_mac_via_proc_net_arp),
            ('arp command', self.get_mac_via_arp_command),
            ('getent', self.get_mac_via_getent),
        ]
        
        for method_name, method_func in methods:
            mac = method_func(ip)
            if mac and mac != '00:00:00:00:00:00':
                # Валидация MAC
                if re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', mac):
                    return mac
        
        return None
    
    def check_host(self, ip):
        """Проверка хоста с расширенной информацией"""
        try:
            # Ping проверка
            result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                  capture_output=True, timeout=2)
            
            if result.returncode == 0:
                mac = self.get_mac_address(ip)
                vendor = self.get_mac_vendor(mac) if mac else 'Unknown'
                hostname = self.get_hostname_methods(ip)
                
                return {
                    'ip': ip,
                    'mac': mac or 'Unknown',
                    'vendor': vendor,
                    'hostname': hostname or 'Unknown',
                    'status': 'up'
                }
        except:
            pass
        return None
    
    def generate_ip_range(self, base_ip, cidr):
        """Генерация диапазона IP"""
        ip_parts = list(map(int, base_ip.split('.')))
        host_bits = 32 - int(cidr)
        num_hosts = 2 ** host_bits - 2
        
        if num_hosts > 1024:
            print(f"⚠️  Обнаружена большая сеть ({num_hosts} хостов)")
            print(f"⚠️  Ограничиваю до 1024 хостов")
            num_hosts = 1024
        
        network = ip_parts[0] << 24 | ip_parts[1] << 16 | ip_parts[2] << 8 | ip_parts[3]
        mask = (0xFFFFFFFF << host_bits) & 0xFFFFFFFF
        network_base = network & mask
        
        ips = []
        for i in range(1, min(num_hosts + 1, 1025)):
            host_ip = network_base + i
            ip_str = f"{(host_ip >> 24) & 0xFF}.{(host_ip >> 16) & 0xFF}.{(host_ip >> 8) & 0xFF}.{host_ip & 0xFF}"
            ips.append(ip_str)
        
        return ips
    
    def scan(self, ip_range=None):
        """Основной метод сканирования"""
        if not ip_range:
            local_ip, cidr = self.get_local_ip()
            if not local_ip:
                print("❌ Не удалось определить локальный IP")
                return
            
            base_ip = '.'.join(local_ip.split('.')[:-1]) + '.0'
            ips = self.generate_ip_range(base_ip, cidr)
            network = f"{base_ip}/{cidr}"
        else:
            # Парсинг CIDR
            if '/' in ip_range:
                base_ip, cidr = ip_range.split('/')
                ips = self.generate_ip_range(base_ip, cidr)
                network = ip_range
            else:
                print("❌ Укажите диапазон в формате CIDR (например: 192.168.1.0/24)")
                return
        
        print(f"\n{'='*70}")
        print(f"  Enhanced Network Scanner v2.0 (Android Compatible)")
        print(f"{'='*70}")
        print(f"🔍 Сканируется: {network} ({len(ips)} хостов)")
        print(f"⚙️  Потоки: {self.threads}")
        print(f"⏱  Таймаут: {self.timeout}с")
        if self.is_termux:
            print(f"📱 Режим: Termux/Android")
        print(f"{'='*70}\n")
        
        start_time = time.time()
        found_count = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_ip = {executor.submit(self.check_host, ip): ip for ip in ips}
            
            for future in as_completed(future_to_ip):
                result = future.result()
                if result:
                    found_count += 1
                    self.results.append(result)
                    self.print_result(result)
        
        elapsed = time.time() - start_time
        
        print(f"\n{'='*70}")
        print(f"✅ Сканирование завершено за {elapsed:.2f}с")
        print(f"📊 Найдено устройств: {found_count}")
        print(f"{'='*70}\n")
    
    def print_result(self, result):
        """Красивый вывод результата"""
        print(f"{'─'*70}")
        print(f"🟢 IP: {result['ip']:<15} │ Hostname: {result['hostname']}")
        print(f"   MAC: {result['mac']:<17} │ Vendor: {result['vendor']}")
        print(f"{'─'*70}")
    
    def export_json(self, filename='scan_results.json'):
        """Экспорт результатов в JSON"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"💾 Результаты сохранены в {filename}")

def main():
    parser = argparse.ArgumentParser(
        description='Enhanced Network Scanner для Android/Termux'
    )
    parser.add_argument('-r', '--range', help='Диапазон IP (CIDR): 192.168.1.0/24')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Количество потоков')
    parser.add_argument('-o', '--output', help='Файл для экспорта (JSON)')
    
    args = parser.parse_args()
    
    scanner = EnhancedNetworkScanner(threads=args.threads)
    scanner.scan(args.range)
    
    if args.output:
        scanner.export_json(args.output)

if __name__ == '__main__':
    main()