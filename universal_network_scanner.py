import socket
import struct
import sys
import subprocess
import re
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import time

class UniversalNetworkScanner:
    def __init__(self, interface=None, timeout=1, threads=50):
        self.interface = interface
        self.timeout = timeout
        self.threads = threads
        self.results = []
        self.os_type = platform.system().lower()
        
    def get_local_ip(self):
        """Получить локальный IP адрес универсально"""
        try:
            # Метод 1: Подключение к внешнему адресу (работает везде)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            
            # Определяем CIDR (обычно /24 для домашних сетей)
            # Пытаемся определить точнее через команды ОС
            cidr = self.get_cidr_for_ip(ip)
            
            return ip, cidr
        except Exception as e:
            print(f"❌ Ошибка получения IP (метод 1): {e}")
            
        # Метод 2: Через hostname (запасной вариант)
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            cidr = '24'  # По умолчанию
            return ip, cidr
        except Exception as e:
            print(f"❌ Ошибка получения IP (метод 2): {e}")
            
        return None, None
    
    def get_cidr_for_ip(self, ip):
        """Определить маску подсети для IP"""
        try:
            if self.os_type == 'linux':
                result = subprocess.run(['ip', 'addr'], 
                                      capture_output=True, text=True, timeout=2)
                pattern = rf'inet {re.escape(ip)}/(\d+)'
                match = re.search(pattern, result.stdout)
                if match:
                    return match.group(1)
                    
            elif self.os_type == 'darwin':  # macOS
                result = subprocess.run(['ifconfig'], 
                                      capture_output=True, text=True, timeout=2)
                # На macOS ищем netmask
                lines = result.stdout.split('\n')
                for i, line in enumerate(lines):
                    if ip in line and i + 1 < len(lines):
                        netmask_match = re.search(r'netmask 0x([0-9a-f]+)', lines[i])
                        if netmask_match:
                            hex_mask = netmask_match.group(1)
                            cidr = bin(int(hex_mask, 16)).count('1')
                            return str(cidr)
                            
            elif self.os_type == 'windows':
                result = subprocess.run(['ipconfig'], 
                                      capture_output=True, text=True, timeout=2)
                lines = result.stdout.split('\n')
                for i, line in enumerate(lines):
                    if ip in line:
                        # Ищем маску подсети в следующих строках
                        for j in range(i, min(i+5, len(lines))):
                            if 'Subnet Mask' in lines[j] or 'Маска подсети' in lines[j]:
                                mask_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', lines[j])
                                if mask_match:
                                    mask = mask_match.group(1)
                                    cidr = self.netmask_to_cidr(mask)
                                    return str(cidr)
        except:
            pass
        
        return '24'  # По умолчанию для домашних сетей
    
    def netmask_to_cidr(self, netmask):
        """Конвертировать маску подсети в CIDR"""
        try:
            return sum([bin(int(x)).count('1') for x in netmask.split('.')])
        except:
            return 24
    
    def get_mac_vendor(self, mac):
        """Определить производителя по MAC адресу"""
        vendors = {
            '00:50:56': 'VMware',
            '08:00:27': 'VirtualBox',
            '52:54:00': 'QEMU/KVM',
            '00:1A:A0': 'Dell',
            '00:1B:63': 'Apple',
            '00:25:00': 'Apple',
            'DC:A6:32': 'Raspberry Pi',
            'B8:27:EB': 'Raspberry Pi',
            '00:0C:29': 'VMware',
            '00:15:5D': 'Microsoft/Hyper-V',
            'F0:18:98': 'Apple',
            'A4:83:E7': 'Apple',
            '78:CA:39': 'Cisco',
            '28:6A:BA': 'D-Link',
            'D8:0D:17': 'TP-Link',
            'EC:08:6B': 'TP-Link',
            '20:E5:2A': 'XIAOMI',
            '64:09:80': 'XIAOMI',
            '18:B9:05': 'Samsung',
            '30:07:4D': 'Samsung',
        }
        
        if not mac:
            return 'Unknown'
            
        prefix = mac[:8].upper()
        return vendors.get(prefix, 'Unknown')
    
    def get_mac_address(self, ip):
        """Получить MAC адрес для IP через ARP (универсально)"""
        try:
            # Ping для заполнения ARP таблицы
            if self.os_type == 'windows':
                ping_cmd = ['ping', '-n', '1', '-w', '1000', ip]
            else:
                ping_cmd = ['ping', '-c', '1', '-W', '1', ip]
            
            subprocess.run(ping_cmd, capture_output=True, timeout=2)
            
            # Чтение ARP таблицы
            if self.os_type == 'windows':
                result = subprocess.run(['arp', '-a', ip], 
                                      capture_output=True, text=True)
            else:
                result = subprocess.run(['arp', '-n', ip], 
                                      capture_output=True, text=True)
            
            # Поиск MAC адреса в выводе
            mac_pattern = r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}'
            match = re.search(mac_pattern, result.stdout)
            if match:
                mac = match.group(0)
                # Нормализация формата (приведение к двоеточиям)
                mac = mac.replace('-', ':').upper()
                return mac
        except:
            pass
        return None
    
    def check_host(self, ip):
        """Проверить доступность хоста"""
        try:
            if self.os_type == 'windows':
                ping_cmd = ['ping', '-n', '1', '-w', '1000', ip]
            else:
                ping_cmd = ['ping', '-c', '1', '-W', '1', ip]
            
            result = subprocess.run(ping_cmd, capture_output=True, timeout=2)
            
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
        num_hosts = 2 ** host_bits - 2
        
        # Ограничение для больших сетей
        if num_hosts > 1024:
            print(f"⚠️  Обнаружена большая сеть ({num_hosts} хостов)")
            print(f"⚠️  Ограничиваю сканирование до 1024 хостов")
            num_hosts = 1024
        
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
                print("\n💡 Попробуйте указать диапазон вручную:")
                print("   python network_scanner.py -r 192.168.1.0/24")
                return
            
            print(f"💻 Операционная система: {platform.system()}")
            print(f"🌐 Локальный IP: {local_ip}/{cidr}")
            ip_range = self.generate_ip_range(local_ip, cidr)
        
        print(f"🔍 Сканирование {len(ip_range)} хостов...")
        print(f"\n{'IP адрес':<15} {'MAC адрес':<18} {'Производитель'}")
        print("-" * 60)
        
        start_time = time.time()
        found = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_host, ip): ip for ip in ip_range}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    ip, mac, vendor = result
                    print(f"{ip:<15} {mac:<18} {vendor}")
                    self.results.append(result)
                    found += 1
        
        elapsed = time.time() - start_time
        print(f"\n✅ Найдено устройств: {len(self.results)}")
        print(f"⏱️  Время сканирования: {elapsed:.2f} сек")

def main():
    parser = argparse.ArgumentParser(
        description='Universal Network Scanner (работает на всех ОС)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  %(prog)s                          # Автоматическое сканирование
  %(prog)s -r 192.168.1.0/24       # Указать диапазон
  %(prog)s -r 172.24.232.0/20      # Большая сеть
  %(prog)s -t 100                   # Использовать 100 потоков
        """
    )
    
    parser.add_argument('-r', '--range', 
                       help='Диапазон IP (например: 192.168.1.0/24)')
    parser.add_argument('-t', '--threads', type=int, default=50,
                       help='Количество потоков (по умолчанию: 50)')
    parser.add_argument('--timeout', type=int, default=1,
                       help='Таймаут в секундах (по умолчанию: 1)')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("  Universal Network Scanner v1.5")
    print("=" * 60 + "\n")
    
    scanner = UniversalNetworkScanner(
        timeout=args.timeout,
        threads=args.threads
    )
    
    if args.range:
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
        import traceback
        traceback.print_exc()
        sys.exit(1)