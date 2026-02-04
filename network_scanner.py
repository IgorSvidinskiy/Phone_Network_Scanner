import socket
import struct
import sys
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import time

class NetworkScanner:
    def __init__(self, interface='wlan0', timeout=1, threads=50):
        self.interface = interface
        self.timeout = timeout
        self.threads = threads
        self.results = []

    def get_local_ip(self):
        """Получить локальный IP адрес"""
        try:
            result = subprocess.run(['ip', 'addr', 'show', self.interface], 
                                  capture_output=True, text=True)
            match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', result.stdout)
            if match:
                ip = match.group(1)
                cidr = match.group(2)
                return ip, cidr
        except Exception as e:
            print(f"Ошибка получения IP: {e}")
        return None, None
    
    def get_mac_vendor(self, mac):
        """Определить производителя по MAC адресу (упрощенная версия)"""
        vendors = {
            '00:50:56': 'VMware',
            '08:00:27': 'VirtualBox',
            '52:54:00': 'QEMU',
            '00:1A:A0': 'Dell',
            '00:1B:63': 'Apple',
            'DC:A6:32': 'Raspberry Pi',
            'B8:27:EB': 'Raspberry Pi',
        }
        
        prefix = mac[:8].upper()
        return vendors.get(prefix, 'Unknown')
    
    def get_mac_address(self, ip):
        """Получить MAC адрес для IP через ARP"""
        try:
            # Попытка ping для заполнения ARP таблицы
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
    
    def check_host(self, ip):
        """Проверить доступность хоста"""
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                  capture_output=True, timeout=2)
            if result.returncode == 0:
                mac = self.get_mac_address(ip)
                if mac:
                    vendor = self.get_mac_vendor(mac)
                    return (ip, mac, vendor)
                return (ip, 'Unknown', 'Unknown')
        except:
            pass
        return None
    
    def generate_ip_range(self, base_ip, cidr):
        """Генерация диапазона IP адресов"""
        ip_parts = list(map(int, base_ip.split('.')))
        host_bits = 32 - int(cidr)
        num_hosts = 2 ** host_bits - 2  # -2 для network и broadcast
        
        # Базовый адрес сети
        network = ip_parts[0] << 24 | ip_parts[1] << 16 | ip_parts[2] << 8 | ip_parts[3]
        mask = (0xFFFFFFFF << host_bits) & 0xFFFFFFFF
        network_base = network & mask
        
        ips = []
        for i in range(1, num_hosts + 1):
            host_ip = network_base + i
            ip_str = f"{(host_ip >> 24) & 0xFF}.{(host_ip >> 16) & 0xFF}.{(host_ip >> 8) & 0xFF}.{host_ip & 0xFF}"
            ips.append(ip_str)
        
        return ips
    
    def scan(self, ip_range=None):
        """Сканировать сеть"""
        if ip_range is None:
            local_ip, cidr = self.get_local_ip()
            if not local_ip:
                print("❌ Не удалось определить локальный IP")
                return
            
            print(f"📱 Интерфейс: {self.interface}")
            print(f"🌐 Локальный IP: {local_ip}/{cidr}")
            ip_range = self.generate_ip_range(local_ip, cidr)
        
        print(f"🔍 Сканирование {len(ip_range)} хостов...\n")
        print(f"{'IP адрес':<15} {'MAC адрес':<18} {'Производитель'}")
        print("-" * 60)
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_threads=self.threads) as executor:
            futures = {executor.submit(self.check_host, ip): ip for ip in ip_range}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    ip, mac, vendor = result
                    print(f"{ip:<15} {mac:<18} {vendor}")
                    self.results.append(result)
        
        elapsed = time.time() - start_time
        print(f"\n✅ Найдено устройств: {len(self.results)}")
        print(f"⏱️  Время сканирования: {elapsed:.2f} сек")

def main():
    parser = argparse.ArgumentParser(
        description='Network Scanner для Termux (аналог netdiscover)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  %(prog)s                          # Автоматическое сканирование
  %(prog)s -i wlan0                 # Указать интерфейс
  %(prog)s -r 192.168.1.0/24       # Указать диапазон
  %(prog)s -t 100                   # Использовать 100 потоков
        """
    )
    
    parser.add_argument('-i', '--interface', default='wlan0',
                       help='Сетевой интерфейс (по умолчанию: wlan0)')
    parser.add_argument('-r', '--range', 
                       help='Диапазон IP (например: 192.168.1.0/24)')
    parser.add_argument('-t', '--threads', type=int, default=50,
                       help='Количество потоков (по умолчанию: 50)')
    parser.add_argument('--timeout', type=int, default=1,
                       help='Таймаут в секундах (по умолчанию: 1)')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("  Network Scanner для Termux v1.0")
    print("=" * 60 + "\n")
    
    scanner = NetworkScanner(
        interface=args.interface,
        timeout=args.timeout,
        threads=args.threads
    )
    
    if args.range:
        # Парсинг указанного диапазона
        match = re.match(r'(\d+\.\d+\.\d+\.\d+)/(\d+)', args.range)
        if match:
            ip_range = scanner.generate_ip_range(match.group(1), match.group(2))
            scanner.scan(ip_range)
        else:
            print("❌ Неверный формат диапазона. Используйте: 192.168.1.0/24")
    else:
        scanner.scan()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Сканирование прервано пользователем")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Ошибка: {e}")
        sys.exit(1)
