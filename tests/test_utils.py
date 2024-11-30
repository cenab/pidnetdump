import pytest
from pidnetdump.utils import is_root, get_process_name
import os
import psutil

def test_is_root():
    expected = os.geteuid() == 0
    assert is_root() == expected

def test_get_process_name():
    current_proc = psutil.Process()
    assert get_process_name(current_proc).lower() == "python" 