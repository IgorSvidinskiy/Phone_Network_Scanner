import socket
import struct
import sys
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import time
import json

class AdvancedNetworkScanner:
    def __init__(self, interface='wlan0', timeout=1, threads=50, scan_ports=False):
        self.interface = interface
        self.timeout = timeout
        self.threads = threads
        self.scan_ports = scan_ports
        self.results = []
        self.common_ports = [22, 80, 443, 8080, 3389, 21, 23, 25, 53, 3306]
        
    def get_local_ip(self):
        """Получить локальный IP адрес и маску подсети"""
        try:
            # Универсальный метод через socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            cidr = '24'  # По умолчанию для локальных сетей
            return ip, cidr
        except Exception as e:
            print(f"❌ Ошибка получения IP: {e}")
        return None, None
    
    def get_gateway(self):
        """Получить адрес шлюза"""
        try:
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True)
            match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
            if match:
                return match.group(1)
        except:
            pass
        return None
    
    def get_mac_vendor(self, mac):
        """Определить производителя по MAC адресу"""
        vendors = {
            '00:50:56': 'VMware',
            '08:00:27': 'VirtualBox',
            '52:54:00': 'QEMU/KVM',
            '00:1A:A0': 'Dell',
            '00:1B:63': 'Apple',
            '00:25:00': 'Apple',
            '00:26:BB': 'Apple',
            'DC:A6:32': 'Raspberry Pi',
            'B8:27:EB': 'Raspberry Pi',
            'E4:5F:01': 'Raspberry Pi',
            '00:0C:29': 'VMware',
            '00:05:69': 'VMware',
            '00:15:5D': 'Microsoft',
            'F0:18:98': 'Apple',
            'A4:83:E7': 'Apple',
            '00:1C:B3': 'Apple',
            '00:17:F2': 'Apple',
            '78:CA:39': 'Cisco',
            '00:1E:13': 'Cisco',
            'FC:15:B4': 'Cisco',
            '00:1D:71': 'Cisco',
            '28:6A:BA': 'D-Link',
            'C8:3A:35': 'Tenda',
            'D8:0D:17': 'TP-Link',
            'EC:08:6B': 'TP-Link',
            '50:C7:BF': 'TP-Link',
            'A0:F3:C1': 'TP-Link',
            '20:E5:2A': 'XIAOMI',
            '64:09:80': 'XIAOMI',
            '34:CE:00': 'XIAOMI',
            '50:8F:4C': 'XIAOMI',
            '78:11:DC': 'XIAOMI',
            'AC:23:3F': 'XIAOMI',
            '18:B9:05': 'Samsung',
            '30:07:4D': 'Samsung',
            '5C:0A:5B': 'Samsung',
            '00:12:FB': 'Samsung',
            '00:16:32': 'Samsung',
            '00:1D:25': 'Samsung',
            '00:21:4C': 'Samsung',
            '00:23:39': 'Samsung',
        }
        
        if not mac:
            return 'Unknown'
            
        prefix = mac[:8].upper()
        return vendors.get(prefix, 'Unknown')
    
    def get_mac_address(self, ip):
        """Получить MAC адрес для IP через ARP"""
        try:
            # Ping для заполнения ARP таблицы
            subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                         capture_output=True, timeout=2)
            
            # Чтение ARP таблицы
            result = subprocess.run(['ip', 'neigh', 'show', ip], 
                                  capture_output=True, text=True)
            
            match = re.search(r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})', 
                            result.stdout)
            if match:
                return match.group(1)
        except:
            pass
        return None
    
    def get_hostname(self, ip):
        """Попытка получить имя хоста"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None
    
    def scan_port(self, ip, port):
        """Проверить открыт ли порт"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def scan_host_ports(self, ip):
        """Сканировать общие порты на хосте"""
        open_ports = []
        for port in self.common_ports:
            if self.scan_port(ip, port):
                open_ports.append(port)
        return open_ports
    
    def check_host(self, ip):
        """Комплексная проверка хоста"""
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                  capture_output=True, timeout=2)
            if result.returncode == 0:
                mac = self.get_mac_address(ip)
                vendor = self.get_mac_vendor(mac)
                hostname = self.get_hostname(ip)
                
                host_info = {
                    'ip': ip,
                    'mac': mac or 'Unknown',
                    'vendor': vendor,
                    'hostname': hostname
                }
                
                if self.scan_ports:
                    open_ports = self.scan_host_ports(ip)
                    host_info['ports'] = open_ports
                
                return host_info
        except:
            pass
        return None
    
    def generate_ip_range(self, base_ip, cidr):
        """Генерация диапазона IP адресов"""
        ip_parts = list(map(int, base_ip.split('.')))
        host_bits = 32 - int(cidr)
        num_hosts = min(2 ** host_bits - 2, 254)
        
        network = ip_parts[0] << 24 | ip_parts[1] << 16 | ip_parts[2] << 8 | ip_parts[3]
        mask = (0xFFFFFFFF << host_bits) & 0xFFFFFFFF
        network_base = network & mask
        
        ips = []
        for i in range(1, num_hosts + 1):
            host_ip = network_base + i
            ip_str = f"{(host_ip >> 24) & 0xFF}.{(host_ip >> 16) & 0xFF}.{(host_ip >> 8) & 0xFF}.{host_ip & 0xFF}"
            ips.append(ip_str)
        
        return ips
    
    def display_results(self):
        """Красивый вывод результатов"""
        if not self.results:
            print("\n❌ Активных хостов не найдено")
            return
        
        print(f"\n{'IP адрес':<15} {'MAC адрес':<18} {'Производитель':<20} {'Имя хоста'}")
        print("-" * 80)
        
        for host in self.results:
            hostname = host.get('hostname', '-')
            if hostname and len(hostname) > 25:
                hostname = hostname[:22] + '...'
            
            print(f"{host['ip']:<15} {host['mac']:<18} {host['vendor']:<20} {hostname or '-'}")
            
            if self.scan_ports and host.get('ports'):
                ports_str = ', '.join(map(str, host['ports']))
                print(f"  └─ Открытые порты: {ports_str}")
    
    def scan(self, ip_range=None):
        """Сканировать сеть"""
        if ip_range is None:
            local_ip, cidr = self.get_local_ip()
            if not local_ip:
                print("❌ Не удалось определить локальный IP")
                return
            
            gateway = self.get_gateway()
            
            print(f"📱 Интерфейс: {self.interface}")
            print(f"🌐 Локальный IP: {local_ip}/{cidr}")
            if gateway:
                print(f"🚪 Шлюз: {gateway}")
            
            ip_range = self.generate_ip_range(local_ip, cidr)
        
        print(f"🔍 Сканирование {len(ip_range)} хостов...")
        if self.scan_ports:
            print("🔌 Включено сканирование портов (это займет больше времени)")
        
        start_time = time.time()
        found = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_host, ip): ip for ip in ip_range}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found += 1
                    self.results.append(result)
                    # Показываем прогресс
                    print(f"✓ Найдено: {found} устройств", end='\r')
        
        elapsed = time.time() - start_time
        
        self.display_results()
        
        print(f"\n✅ Найдено устройств: {len(self.results)}")
        print(f"⏱️  Время сканирования: {elapsed:.2f} сек")
    
    def export_json(self, filename='scan_results.json'):
        """Экспорт результатов в JSON"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"💾 Результаты сохранены в {filename}")
        except Exception as e:
            print(f"❌ Ошибка сохранения: {e}")

def main():
    parser = argparse.ArgumentParser(
        description='Advanced Network Scanner для Termux',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  %(prog)s                          # Базовое сканирование
  %(prog)s -i wlan0                 # Указать интерфейс
  %(prog)s -r 192.168.1.0/24       # Указать диапазон
  %(prog)s -p                       # Сканировать порты
  %(prog)s -o results.json         # Экспорт в JSON
  %(prog)s -t 100 -p               # Быстрое сканирование с портами
        """
    )
    
    parser.add_argument('-i', '--interface', default='wlan0',
                       help='Сетевой интерфейс (по умолчанию: wlan0)')
    parser.add_argument('-r', '--range', 
                       help='Диапазон IP (например: 192.168.1.0/24)')
    parser.add_argument('-t', '--threads', type=int, default=50,
                       help='Количество потоков (по умолчанию: 50)')
    parser.add_argument('-p', '--ports', action='store_true',
                       help='Сканировать общие порты')
    parser.add_argument('-o', '--output',
                       help='Экспорт результатов в JSON файл')
    parser.add_argument('--timeout', type=int, default=1,
                       help='Таймаут в секундах (по умолчанию: 1)')
    
    args = parser.parse_args()
    
    print("=" * 80)
    print("  Advanced Network Scanner для Termux v2.0")
    print("=" * 80 + "\n")
    
    scanner = AdvancedNetworkScanner(
        interface=args.interface,
        timeout=args.timeout,
        threads=args.threads,
        scan_ports=args.ports
    )
    
    if args.range:
        match = re.match(r'(\d+\.\d+\.\d+\.\d+)/(\d+)', args.range)
        if match:
            ip_range = scanner.generate_ip_range(match.group(1), match.group(2))
            scanner.scan(ip_range)
        else:
            print("❌ Неверный формат диапазона. Используйте: 192.168.1.0/24")
            return
    else:
        scanner.scan()
    
    if args.output:
        scanner.export_json(args.output)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Сканирование прервано пользователем")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Ошибка: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)