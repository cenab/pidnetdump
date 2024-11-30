import os
import sys
import threading
import time
import argparse
import logging
import subprocess
from datetime import datetime
import select
import re

def is_root():
    return os.geteuid() == 0

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Real-time network monitoring for a specific PID using tcpdump.'
    )
    parser.add_argument(
        'pid',
        type=int,
        help='Process ID to monitor'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    parser.add_argument(
        '--interval',
        type=int,
        default=5,
        help='Update interval in seconds (default: 5)'
    )
    args = parser.parse_args()
    return args

def setup_logging(debug=False):
    log_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        force=True
    )

class NetTopMonitor(threading.Thread):
    def __init__(self, pid, interval=5):
        super().__init__(name='NetTopMonitor')
        self.pid = pid
        self.interval = interval
        self.running = True
        self.active_ports = set()
        self.tcpdump_proc = None

    def get_active_ports(self):
        active_ports = set()
        try:
            # Use nettop with -x for raw output
            nettop_cmd = [
                'nettop',
                '-P',
                '-L', '1',
                '-x',
                '-p', str(self.pid)
            ]
            result = subprocess.run(nettop_cmd, capture_output=True, text=True)
            output = result.stdout
            logging.debug(f"Raw nettop output:\n{output}")

            # Skip header lines
            lines = output.strip().split('\n')
            for line in lines:
                logging.debug(f"Parsing line: {line}")
                # Adjust the regex to match the nettop output
                # Example line:
                # TCP 4 192.168.1.98:64405<->2a03:2880:f201:c6:face:b00c:0:7260:443 en1 Established
                match = re.search(r'\S+\s+\S+\s+([\d\.:]+):(\d+)<->([\d\.:]+):(\d+)', line)
                if match:
                    local_ip = match.group(1)
                    local_port = int(match.group(2))
                    remote_ip = match.group(3)
                    remote_port = int(match.group(4))
                    active_ports.add(local_port)
                    active_ports.add(remote_port)
                    logging.debug(f"Found ports: {local_port}, {remote_port}")
                else:
                    logging.debug("No match found for line")

            logging.debug(f"Active ports from nettop: {active_ports}")
        except Exception as e:
            logging.error(f"Error retrieving active ports: {e}")
        return active_ports

    def run(self):
        logging.debug(f"Starting NetTopMonitor for PID {self.pid}")

        last_update_time = 0

        while self.running:
            now = time.time()
            if now - last_update_time >= self.interval:
                last_update_time = now
                current_ports = self.get_active_ports()

                if not current_ports:
                    logging.info("No active network connections found for the process")
                    time.sleep(self.interval)
                    continue

                if current_ports != self.active_ports:
                    self.active_ports = current_ports
                    # Restart tcpdump with new filter
                    if self.tcpdump_proc:
                        logging.debug("Ports have changed, restarting tcpdump")
                        self.tcpdump_proc.terminate()
                        try:
                            self.tcpdump_proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            self.tcpdump_proc.kill()
                    else:
                        logging.debug("Starting tcpdump")

                    # Build the tcpdump filter expression
                    port_filters = [f'port {port}' for port in self.active_ports]
                    filter_expr = ' or '.join(port_filters)

                    tcpdump_cmd = [
                        'tcpdump',
                        '-i', 'any',
                        '-n',
                        '-l',
                        '-vv',
                        filter_expr
                    ]

                    logging.debug(f"Running tcpdump with filter: {filter_expr}")

                    try:
                        self.tcpdump_proc = subprocess.Popen(
                            tcpdump_cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            bufsize=1
                        )
                    except Exception as e:
                        logging.error(f"Error starting tcpdump: {e}")
                        self.running = False
                        break

            # Read tcpdump output
            if self.tcpdump_proc and self.tcpdump_proc.stdout:
                ready, _, _ = select.select([self.tcpdump_proc.stdout], [], [], 1)
                if ready:
                    line = self.tcpdump_proc.stdout.readline()
                    if line:
                        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
                        print(f"[{timestamp}] {line.strip()}")
                else:
                    time.sleep(0.1)
            else:
                time.sleep(0.1)

        # Cleanup
        if self.tcpdump_proc:
            self.tcpdump_proc.terminate()
            try:
                self.tcpdump_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.tcpdump_proc.kill()

    def stop(self):
        logging.debug("Stop signal received...")
        self.running = False

def main():
    args = parse_arguments()
    setup_logging(debug=args.debug)

    if not is_root():
        logging.error("Script must be run as root")
        sys.exit(1)

    logging.info(f"Monitoring network activity for PID {args.pid} using tcpdump...")

    nettop_monitor = NetTopMonitor(args.pid, interval=args.interval)

    try:
        nettop_monitor.start()
        while nettop_monitor.running:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Keyboard interrupt received")
    finally:
        nettop_monitor.stop()
        nettop_monitor.join()
        logging.info("Tool stopped")

if __name__ == '__main__':
    main()
