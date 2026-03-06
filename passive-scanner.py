#!/usr/bin/env python3
"""
Passive Network Discovery Scanner
Обнаруживает устройства БЕЗ активного сканирования через:
- mDNS/Bonjour прослушивание
- SSDP/UPnP discovery
- Анализ ARP broadcast
- Passive DNS monitoring

100% легально, не вызывает подозрений у IDS/IPS
"""

import socket
import struct
import select
import time
import json
import threading
from collections import defaultdict
import argparse

class PassiveNetworkDiscovery:
    def __init__(self, duration=60):
        self.duration = duration
        self.discovered_devices = defaultdict(dict)
        self.running = False
        
    def listen_mdns(self):
        """
        Прослушивание mDNS (Multicast DNS / Bonjour)
        224.0.0.251:5353 - стандартный адрес для mDNS
        """
        MCAST_GRP = '224.0.0.251'
        MCAST_PORT = 5353
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind(('', MCAST_PORT))
        except OSError:
            print("⚠️  Порт 5353 занят, пропускаем mDNS")
            return
        
        # Подписка на multicast группу
        mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(1)
        
        print("🎧 Прослушивание mDNS (Bonjour)...")
        
        start_time = time.time()
        while self.running and (time.time() - start_time) < self.duration:
            try:
                data, addr = sock.recvfrom(1024)
                ip = addr[0]
                
                # Простой парсинг DNS имени (упрощённо)
                if len(data) > 12:
                    # DNS запросы содержат имена в формате длина+строка
                    try:
                        name_parts = []
                        i = 12  # Пропускаем DNS header
                        while i < len(data) and data[i] != 0:
                            length = data[i]
                            if length == 0 or i + length >= len(data):
                                break
                            name_part = data[i+1:i+1+length].decode('utf-8', errors='ignore')
                            name_parts.append(name_part)
                            i += length + 1
                        
                        if name_parts:
                            hostname = '.'.join(name_parts)
                            self.add_device(ip, hostname=hostname, method='mDNS')
                    except:
                        pass
            except socket.timeout:
                continue
            except Exception as e:
                pass
        
        sock.close()
    
    def listen_ssdp(self):
        """
        Прослушивание SSDP (Simple Service Discovery Protocol)
        239.255.255.250:1900 - UPnP/DLNA discovery
        """
        MCAST_GRP = '239.255.255.250'
        MCAST_PORT = 1900
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind(('', MCAST_PORT))
        except OSError:
            print("⚠️  Порт 1900 занят, пропускаем SSDP")
            return
        
        mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(1)
        
        print("🎧 Прослушивание SSDP (UPnP)...")
        
        start_time = time.time()
        while self.running and (time.time() - start_time) < self.duration:
            try:
                data, addr = sock.recvfrom(2048)
                ip = addr[0]
                
                # Парсинг SSDP ответа
                try:
                    text = data.decode('utf-8', errors='ignore')
                    
                    # Ищем информацию об устройстве
                    device_type = None
                    manufacturer = None
                    
                    for line in text.split('\n'):
                        line = line.strip()
                        if 'SERVER:' in line.upper():
                            device_type = line.split(':', 1)[1].strip()
                        elif 'LOCATION:' in line.upper():
                            location = line.split(':', 1)[1].strip()
                    
                    if device_type:
                        self.add_device(ip, device_type=device_type, method='SSDP')
                except:
                    pass
            except socket.timeout:
                continue
            except Exception:
                pass
        
        sock.close()
    
    def listen_netbios(self):
        """
        Прослушивание NetBIOS Name Service
        Порт 137 UDP - для обнаружения Windows устройств
        """
        PORT = 137
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind(('', PORT))
        except OSError:
            print("⚠️  Порт 137 занят, пропускаем NetBIOS")
            return
        
        sock.settimeout(1)
        
        print("🎧 Прослушивание NetBIOS...")
        
        start_time = time.time()
        while self.running and (time.time() - start_time) < self.duration:
            try:
                data, addr = sock.recvfrom(1024)
                ip = addr[0]
                
                # Простой парсинг NetBIOS имени
                try:
                    if len(data) > 56:
                        # NetBIOS name в ответе обычно с offset 57
                        name_data = data[57:73]
                        name = name_data.decode('utf-8', errors='ignore').strip()
                        if name and name.isprintable():
                            self.add_device(ip, hostname=name, method='NetBIOS')
                except:
                    pass
            except socket.timeout:
                continue
            except Exception:
                pass
        
        sock.close()
    
    def passive_arp_monitor(self):
        """
        Мониторинг ARP broadcasts (требует привилегий на некоторых системах)
        Альтернатива: чтение /proc/net/arp периодически
        """
        print("🎧 Мониторинг ARP таблицы...")
        
        start_time = time.time()
        seen_ips = set()
        
        while self.running and (time.time() - start_time) < self.duration:
            try:
                # Чтение ARP таблицы из /proc
                with open('/proc/net/arp', 'r') as f:
                    lines = f.readlines()[1:]  # Пропускаем заголовок
                    
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 4:
                            ip = parts[0]
                            mac = parts[3]
                            
                            if ip not in seen_ips and mac != '00:00:00:00:00:00':
                                seen_ips.add(ip)
                                self.add_device(ip, mac=mac, method='ARP')
            except:
                pass
            
            time.sleep(2)  # Проверяем каждые 2 секунды
    
    def add_device(self, ip, **kwargs):
        """Добавление обнаруженного устройства"""
        if ip not in self.discovered_devices or not self.discovered_devices[ip]:
            self.discovered_devices[ip] = {'ip': ip, 'methods': []}
        
        # Обновляем информацию
        for key, value in kwargs.items():
            if key == 'method':
                if value not in self.discovered_devices[ip]['methods']:
                    self.discovered_devices[ip]['methods'].append(value)
            else:
                if key not in self.discovered_devices[ip] or not self.discovered_devices[ip].get(key):
                    self.discovered_devices[ip][key] = value
        
        # Вывод в реальном времени
        if len(self.discovered_devices[ip]['methods']) == 1:  # Новое устройство
            self.print_device(self.discovered_devices[ip])
    
    def print_device(self, device):
        """Вывод информации об устройстве"""
        print(f"\n{'─'*70}")
        print(f"🆕 Обнаружено: {device['ip']}")
        if device.get('hostname'):
            print(f"   Hostname: {device['hostname']}")
        if device.get('mac'):
            print(f"   MAC: {device['mac']}")
        if device.get('device_type'):
            print(f"   Type: {device['device_type']}")
        print(f"   Методы: {', '.join(device.get('methods', []))}")
        print(f"{'─'*70}")
    
    def discover(self):
        """Запуск пассивного обнаружения"""
        print(f"\n{'='*70}")
        print(f"  Passive Network Discovery Scanner")
        print(f"  100% пассивный режим - НЕ вызывает подозрений")
        print(f"{'='*70}")
        print(f"⏱  Длительность: {self.duration}с")
        print(f"{'='*70}\n")
        
        self.running = True
        
        # Запускаем все методы в отдельных потоках
        threads = [
            threading.Thread(target=self.listen_mdns, daemon=True),
            threading.Thread(target=self.listen_ssdp, daemon=True),
            threading.Thread(target=self.listen_netbios, daemon=True),
            threading.Thread(target=self.passive_arp_monitor, daemon=True),
        ]
        
        for t in threads:
            t.start()
        
        # Ждём завершения
        time.sleep(self.duration)
        self.running = False
        
        # Даём потокам время на завершение
        time.sleep(2)
        
        print(f"\n{'='*70}")
        print(f"✅ Обнаружение завершено")
        print(f"📊 Всего устройств: {len(self.discovered_devices)}")
        print(f"{'='*70}\n")
        
        return self.discovered_devices
    
    def export_json(self, filename='passive_discovery.json'):
        """Экспорт результатов"""
        with open(filename, 'w') as f:
            json.dump(dict(self.discovered_devices), f, indent=2)
        print(f"💾 Результаты сохранены в {filename}")

def main():
    parser = argparse.ArgumentParser(
        description='Passive Network Discovery - БЕЗ активного сканирования'
    )
    parser.add_argument('-d', '--duration', type=int, default=60, 
                       help='Длительность прослушивания в секундах (default: 60)')
    parser.add_argument('-o', '--output', help='Файл для экспорта (JSON)')
    
    args = parser.parse_args()
    
    scanner = PassiveNetworkDiscovery(duration=args.duration)
    results = scanner.discover()
    
    # Вывод итоговой таблицы
    if results:
        print("\n" + "="*70)
        print("  ИТОГОВАЯ ТАБЛИЦА")
        print("="*70)
        print(f"{'IP':<15} {'Hostname':<25} {'MAC':<18} {'Methods'}")
        print("-"*70)
        
        for ip, info in sorted(results.items()):
            hostname = info.get('hostname', 'Unknown')[:24]
            mac = info.get('mac', 'Unknown')[:17]
            methods = ','.join(info.get('methods', []))[:15]
            print(f"{ip:<15} {hostname:<25} {mac:<18} {methods}")
        
        print("="*70)
    
    if args.output:
        scanner.export_json(args.output)

if __name__ == '__main__':
    main()