import sys
import threading
import time
import psutil
from scapy.all import sniff, IP, IPv6, TCP, UDP
from datetime import datetime
import argparse
from .utils import is_root, get_process_name

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Real-time network packet monitoring for a specific PID.'
    )
    parser.add_argument(
        'pid',
        type=int,
        help='Process ID to monitor'
    )
    parser.add_argument(
        '-i', '--interface',
        type=str,
        default=None,
        help='Network interface to listen on (default: all interfaces)'
    )
    parser.add_argument(
        '-p', '--protocol',
        type=str,
        choices=['tcp', 'udp', 'all'],
        default='all',
        help='Protocol to filter (default: all)'
    )
    parser.add_argument(
        '-l', '--logfile',
        type=str,
        default=None,
        help='Log output to a file'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    return parser.parse_args()

class ConnectionMonitor(threading.Thread):
    def __init__(self, pid, update_interval=1):
        super().__init__()
        self.pid = pid
        self.update_interval = update_interval
        self.connections = set()
        self.running = True
        self.lock = threading.Lock()

    def run(self):
        while self.running:
            self.update_connections()
            time.sleep(self.update_interval)

    def update_connections(self):
        with self.lock:
            new_connections = set()
            try:
                proc = psutil.Process(self.pid)
                conns = proc.connections(kind='inet')
                for conn in conns:
                    if conn.status == psutil.CONN_ESTABLISHED:
                        laddr = (conn.laddr.ip, conn.laddr.port)
                        raddr = (conn.raddr.ip, conn.raddr.port) if conn.raddr else None
                        new_connections.add((laddr, raddr))
            except psutil.NoSuchProcess:
                print(f"Process with PID {self.pid} does not exist.")
                self.running = False
                return
            except psutil.AccessDenied:
                print(f"Access denied to process with PID {self.pid}.")
                self.running = False
                return
            except Exception as e:
                print(f"Error retrieving connections: {e}")
                self.running = False
                return
            self.connections = new_connections

    def stop(self):
        self.running = False

class PacketSniffer(threading.Thread):
    def __init__(self, connection_monitor, iface=None, protocol='all', logfile=None, verbose=False):
        super().__init__()
        self.connection_monitor = connection_monitor
        self.iface = iface
        self.protocol = protocol
        self.logfile = logfile
        self.verbose = verbose
        self.running = True

    def run(self):
        if self.protocol == 'tcp':
            filter_proto = 'tcp'
        elif self.protocol == 'udp':
            filter_proto = 'udp'
        else:
            filter_proto = 'tcp or udp'

        sniff_kwargs = {
            'prn': self.process_packet,
            'store': False,
            'stop_filter': self.stop_sniffing,
            'filter': filter_proto,
        }
        if self.iface:
            sniff_kwargs['iface'] = self.iface

        sniff(**sniff_kwargs)

    def process_packet(self, packet):
        if not packet.haslayer(IP) and not packet.haslayer(IPv6):
            return

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        src_ip = packet[IP].src if packet.haslayer(IP) else packet[IPv6].src
        dst_ip = packet[IP].dst if packet.haslayer(IP) else packet[IPv6].dst
        src_port = None
        dst_port = None

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            return  # Skip non-TCP/UDP packets

        with self.connection_monitor.lock:
            for conn in self.connection_monitor.connections:
                laddr, raddr = conn
                # Check if packet matches local or remote address
                if ((src_ip, src_port) == laddr or (dst_ip, dst_port) == laddr or
                    (src_ip, src_port) == raddr or (dst_ip, dst_port) == raddr):
                    self.display_packet(packet, timestamp)
                    break

    def display_packet(self, packet, timestamp):
        output = f"[{timestamp}] {packet.summary()}"
        if self.verbose:
            output += f"\n{packet.show(dump=True)}"
        print(output)
        if self.logfile:
            with open(self.logfile, 'a') as f:
                f.write(output + '\n')

    def stop_sniffing(self, packet):
        return not self.running

    def stop(self):
        self.running = False

def main():
    if not is_root():
        print("This script must be run as root.")
        sys.exit(1)

    args = parse_arguments()

    try:
        proc = psutil.Process(args.pid)
        proc_name = get_process_name(proc)
    except psutil.NoSuchProcess:
        print(f"Process with PID {args.pid} does not exist.")
        sys.exit(1)
    except psutil.AccessDenied:
        print(f"Access denied to process with PID {args.pid}.")
        sys.exit(1)

    print(f"Monitoring network packets for PID {args.pid} ({proc_name})...")

    connection_monitor = ConnectionMonitor(args.pid)
    packet_sniffer = PacketSniffer(
        connection_monitor,
        iface=args.interface,
        protocol=args.protocol,
        logfile=args.logfile,
        verbose=args.verbose
    )

    try:
        connection_monitor.start()
        packet_sniffer.start()
        while connection_monitor.running and packet_sniffer.running:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping the tool...")
    finally:
        connection_monitor.stop()
        packet_sniffer.stop()
        connection_monitor.join()
        packet_sniffer.join()

if __name__ == '__main__':
    main()
