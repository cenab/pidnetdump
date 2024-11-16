import os

def is_root():
    return os.geteuid() == 0

def get_process_name(proc):
    try:
        return proc.name()
    except Exception:
        return 'Unknown'
