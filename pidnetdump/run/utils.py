# utils.py

import os
import argparse
import logging

def is_root():
    """
    Check if the script is running as root.
    """
    return os.geteuid() == 0

def parse_arguments():
    """
    Parse command-line arguments.
    """
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
    """
    Set up logging configuration.
    """
    log_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        force=True
    )
