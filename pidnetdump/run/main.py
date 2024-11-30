# main.py

import sys
import time
import logging
from pidnetdump.utils import is_root, parse_arguments, setup_logging
from pidnetdump.run.nettop_monitor import NetTopMonitor

def main():
    """
    Main entry point of the script.
    """
    args = parse_arguments()
    setup_logging(verbose=args.debug)

    if not is_root():
        logging.error("Script must be run as root")
        return 1

    logging.info(f"Monitoring network activity for PID {args.pid} using tcpdump...")

    nettop_monitor = NetTopMonitor(args.pid, interval=args.interval)

    try:
        nettop_monitor.start()
        while nettop_monitor.is_running:
            time.sleep(0.1)
    except KeyboardInterrupt:
        logging.info("Keyboard interrupt received")
    except Exception as e:
        logging.error(f"Error monitoring process: {e}")
    finally:
        nettop_monitor.stop()

    return 0

if __name__ == '__main__':
    main()
