# nettop_monitor.py

import threading
import time
import subprocess
from processportmonitor import ProcessPortMonitor
import logging
from datetime import datetime

class NetTopMonitor(threading.Thread):
    """
    A thread that monitors network activity for a specific PID using nettop and tcpdump.
    """
    def __init__(self, pid, interval=1.0):
        super().__init__()
        self._pid = pid
        self._interval = interval
        self._stop_event = threading.Event()
        self.is_running = False
        self._tcpdump_process = None
        
        def port_callback(new_ports, closed_ports, active_ports, port_history):
            if new_ports:
                for port in new_ports:
                    logging.info(f"New connection established on port {port}")
            if closed_ports:
                for port in closed_ports:
                    logging.info(f"Connection closed on port {port}")
            if active_ports:
                logging.debug(f"Currently active ports: {active_ports}")
            
            # Update tcpdump filter when ports change
            if new_ports or closed_ports:
                self._update_tcpdump(active_ports)

        # Initialize the port monitor with our callback
        self._port_monitor = ProcessPortMonitor(
            pid=self._pid,
            interval=self._interval,
            callback=port_callback
        )

    def _update_tcpdump(self, active_ports):
        # Stop existing tcpdump if running
        if self._tcpdump_process:
            self._tcpdump_process.terminate()
            self._tcpdump_process.wait()

        if not active_ports:
            return

        # Build tcpdump filter for active ports
        port_filter = ' or '.join(f'port {port}' for port in active_ports)
        cmd = [
            'tcpdump',
            '-i', 'any',  # Listen on any interface
            '-n',         # Don't convert addresses
            '-l',         # Line-buffered output
            port_filter
        ]

        try:
            self._tcpdump_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Line buffered
            )
            
            # Start a thread to read tcpdump output
            threading.Thread(
                target=self._read_tcpdump_output,
                daemon=True
            ).start()
        except subprocess.SubprocessError as e:
            logging.error(f"Failed to start tcpdump: {e}")

    def _read_tcpdump_output(self):
        """Read and log tcpdump output"""
        while self._tcpdump_process and not self._stop_event.is_set():
            line = self._tcpdump_process.stdout.readline()
            if not line:
                break
            logging.info(f"Traffic: {line.strip()}")

    def run(self):
        """
        Main thread execution method.
        """
        self.is_running = True
        try:
            self._port_monitor.start()
            while not self._stop_event.is_set():
                time.sleep(self._interval)
        except Exception as e:
            logging.error(f"Error in monitor: {e}")
            self.is_running = False
        finally:
            self.is_running = False

    def stop(self):
        """
        Signal the thread to stop running.
        """
        logging.debug("Stop signal received...")
        self._stop_event.set()
        try:
            self._port_monitor.stop()
        except Exception as e:
            logging.error(f"Error stopping port monitor: {e}")
