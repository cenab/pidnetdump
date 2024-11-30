import pytest
import subprocess
import time

@pytest.fixture
def mock_process():
    # Start a simple Python HTTP server as a test process
    proc = subprocess.Popen(
        ["python3", "-m", "http.server", "8000"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    time.sleep(1)  # Give the server time to start
    yield proc.pid
    proc.terminate()
    proc.wait()

@pytest.fixture
def root_required():
    """Skip test if not running as root"""
    import os
    if os.geteuid() != 0:
        pytest.skip("This test requires root privileges") 