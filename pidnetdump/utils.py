# utils.py
import os
import psutil
import argparse
import logging

def is_root():
    """Check if the script is running with root privileges."""
    return os.geteuid() == 0

def get_process_name(proc):
    """Get process name, ensuring consistent case."""
    return proc.name().lower()

def validate_pid(pid):
    """Check if the given PID exists."""
    try:
        process = psutil.Process(pid)
        return True
    except psutil.NoSuchProcess:
        return False

def parse_arguments():
    parser = argparse.ArgumentParser(description='Network traffic dumper by PID')
    parser.add_argument('-p', '--pid', type=int, required=True,
                      help='Process ID to monitor')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output')
    parser.add_argument('-i', '--interval', type=float, default=1.0,
                      help='Monitoring interval in seconds (default: 1.0)')
    args = parser.parse_args()
    
    # Validate PID
    if not validate_pid(args.pid):
        parser.error(f"PID {args.pid} does not exist")
    
    return args

def setup_logging(verbose=False):
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logging.getLogger(__name__)
