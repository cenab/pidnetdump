# pidnetdump

Real-time network packet monitoring for a specific PID.

## Features

- Monitor network packets associated with a specific Process ID (PID) in real time.
- Supports IPv4 and IPv6.
- Filter by protocol (TCP, UDP, or both).
- Specify network interface to listen on.
- Option to log output to a file.
- Verbose mode for detailed packet information.

## Installation

```bash
git clone https://github.com/cenab/pidnetdump.git
cd pidnetdump
python3 setup.py install
```

_Note: You may need to run the installation command with `sudo` if you encounter permission issues._

## Usage

```bash
pidnetdump <pid> [options]
```

## Options

- `PID`: Process ID to monitor.
- `-i`, `--interface`: Network interface to listen on (default: all interfaces).
- `-p`, `--protocol`: Protocol to filter (`tcp`, `udp`, or `all`; default: `all`).
- `-l`, `--logfile`: Log output to a file.
- `-v`, `--verbose`: Enable verbose output.

## Example

```bash
sudo pidnetdump -i eth0 -p tcp 1234
```

## Requirements

- Python 3.x
- [psutil](https://pypi.org/project/psutil/) >= 5.8.0
- [Scapy](https://pypi.org/project/scapy/) >= 2.4.5

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

