# utils.py
import os
import psutil

def is_root():
    return os.geteuid() == 0

def get_process_name(proc):
    return proc.name()
