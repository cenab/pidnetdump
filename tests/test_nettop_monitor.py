import pytest
from processportmonitor import ProcessPortMonitor
import time

def test_nettop_monitor_initialization():
    monitor = ProcessPortMonitor(pid=1234, interval=1)
    assert monitor.pid == 1234
    assert monitor.interval == 1
    assert isinstance(monitor.port_history, list)
    assert hasattr(monitor, 'start')
    assert hasattr(monitor, 'stop')
    assert hasattr(monitor, 'callback')

@pytest.mark.usefixtures("root_required")
def test_nettop_monitor_with_real_process(mock_process):
    def port_callback(new_ports, closed_ports, active_ports, port_history):
        nonlocal ports_found
        if 8000 in active_ports:
            ports_found = True
    
    ports_found = False
    monitor = ProcessPortMonitor(pid=mock_process, interval=1, callback=port_callback)
    monitor.start()
    
    # Wait for port detection
    timeout = time.time() + 5  # 5 second timeout
    while not ports_found and time.time() < timeout:
        time.sleep(0.1)
    
    monitor.stop()
    monitor.join()
    
    assert ports_found, "Port 8000 was not detected"