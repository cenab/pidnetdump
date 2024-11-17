import sys
import threading
import time
import argparse
import logging
import subprocess
from datetime import datetime
from .utils import is_root, get_process_name

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Real-time network monitoring for a specific PID using nettop.'
    )
    parser.add_argument(
        'pid',
        type=int,
        help='Process ID to monitor'
    )
    parser.add_argument(
        '-l', '--logfile',
        type=str,
        default=None,
        help='Log output to a file'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    parser.add_argument(
        '--interval',
        type=int,
        default=1,
        help='Update interval in seconds (default: 1)'
    )
    return parser.parse_args()

def setup_logging(debug=False):
    log_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

class NetTopMonitor(threading.Thread):
    def __init__(self, pid, interval=1, logfile=None):
        super().__init__(name='NetTopMonitor')
        self.pid = pid
        self.interval = interval
        self.logfile = logfile
        self.running = True

    def run(self):
        logging.debug(f"Starting NetTopMonitor for PID {self.pid}")
        cmd = [
            'nettop', '-P', '-p', str(self.pid), '-L', '0',
            '-s', str(self.interval), '-x'
        ]
        logging.debug(f"Running command: {' '.join(cmd)}")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        try:
            header = process.stdout.readline()
            logging.debug(f"Header: {header.strip()}")
            while self.running:
                output = process.stdout.readline()
                if output:
                    self.process_output(output.strip())
                else:
                    time.sleep(self.interval)
        except Exception as e:
            logging.exception(f"Error in NetTopMonitor: {e}")
        finally:
            process.terminate()
            logging.debug("NetTopMonitor stopped.")

    def process_output(self, output):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        logging.debug(f"Raw output: {output}")
        try:
            columns = output.split(',')
            if len(columns) >= 20:
                # Adjust indices based on the columns output by nettop
                nettop_time = columns[0]
                proc_name_pid = columns[1]  # This includes process name and PID
                interface = columns[2]
                state = columns[3]
                bytes_in = columns[4]
                bytes_out = columns[5]
                rx_dupe = columns[6]
                rx_ooo = columns[7]
                re_tx = columns[8]
                rtt_avg = columns[9]
                rcvsize = columns[10]
                tx_win = columns[11]
                tc_class = columns[12]
                tc_mgt = columns[13]
                cc_algo = columns[14]
                P = columns[15]
                C = columns[16]
                R = columns[17]
                W = columns[18]
                arch = columns[19]

                output_line = (
                    f"[{timestamp}] Process: {proc_name_pid}, "
                    f"Interface: {interface}, State: {state}, "
                    f"Bytes In: {bytes_in}, Bytes Out: {bytes_out}, "
                    f"RX Dup: {rx_dupe}, RX OOO: {rx_ooo}, Re-Tx: {re_tx}, "
                    f"RTT Avg: {rtt_avg}, RcvSize: {rcvsize}, TxWin: {tx_win}"
                )
                print(output_line)
                if self.logfile:
                    with open(self.logfile, 'a') as f:
                        f.write(output_line + '\n')
            else:
                logging.debug("Output does not have enough columns. Skipping.")
        except Exception as e:
            logging.exception(f"Error processing output: {e}")

    def stop(self):
        logging.debug("Stopping NetTopMonitor...")
        self.running = False

def main():
    args = parse_arguments()
    setup_logging(debug=args.debug)

    if not is_root():
        logging.error("This script must be run as root.")
        sys.exit(1)

    try:
        import psutil
        proc = psutil.Process(args.pid)
        proc_name = get_process_name(proc)
    except psutil.NoSuchProcess:
        logging.error(f"Process with PID {args.pid} does not exist.")
        sys.exit(1)
    except psutil.AccessDenied:
        logging.error(f"Access denied to process with PID {args.pid}.")
        sys.exit(1)
    except Exception as e:
        logging.exception(f"Error accessing process with PID {args.pid}: {e}")
        sys.exit(1)

    logging.info(f"Monitoring network activity for PID {args.pid} ({proc_name}) using nettop...")

    nettop_monitor = NetTopMonitor(args.pid, interval=args.interval, logfile=args.logfile)

    try:
        nettop_monitor.start()
        while nettop_monitor.running:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Keyboard interrupt received. Stopping the tool...")
    finally:
        nettop_monitor.stop()
        nettop_monitor.join()
        logging.info("Tool stopped.")

if __name__ == '__main__':
    main()
