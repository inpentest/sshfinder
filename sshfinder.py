import argparse
import sys
import logging
import warnings
from scapy.all import IP, TCP, sr, send, conf
import paramiko

# Suppress warnings and unnecessary output
conf.ipv6_enabled = False
conf.verb = 0
warnings.filterwarnings("ignore", category=DeprecationWarning)
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

def parse_arguments():
    parser = argparse.ArgumentParser(description='Scan for open SSH ports using Scapy.')
    parser.add_argument('target', help='Target IP address or DNS name')
    parser.add_argument('-p', '--ports', default='1-65535', help='Port range to scan (default: 1-65535)')
    return parser.parse_args()

def parse_port_range(port_range_str):
    try:
        start_port, end_port = map(int, port_range_str.split('-'))
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            raise ValueError
        return start_port, end_port
    except ValueError:
        print('Invalid port range. Please use the format start-end (e.g., 1-65535).')
        sys.exit(1)

def scan_ports_scapy(host, start_port, end_port):
    ports = list(range(start_port, end_port + 1))
    open_ports = []
    packets = IP(dst=host)/TCP(dport=ports, flags='S')
    answered, _ = sr(packets, timeout=1, verbose=0)
    for _, received in answered:
        tcp_layer = received.getlayer(TCP)
        if tcp_layer.flags == 0x12:
            open_ports.append(tcp_layer.sport)
            send(IP(dst=host)/TCP(dport=tcp_layer.sport, flags='R'), verbose=0)
    return open_ports

def validate_ssh_ports(host, open_ports):
    ssh_ports = []
    for port in open_ports:
        try:
            transport = paramiko.Transport((host, port))
            transport.start_client(timeout=5)
            ssh_ports.append(port)
        except paramiko.ssh_exception.SSHException:
            pass
        except Exception:
            pass
        finally:
            if 'transport' in locals():
                transport.close()
    return ssh_ports

def main():
    args = parse_arguments()
    host = args.target
    start_port, end_port = parse_port_range(args.ports)
    print(f'Scanning ports {start_port}-{end_port} on {host}...')
    try:
        open_ports = scan_ports_scapy(host, start_port, end_port)
        if open_ports:
            print(f'Open ports on {host}: {open_ports}')
            print('Validating SSH ports...')
            ssh_ports = validate_ssh_ports(host, open_ports)
            if ssh_ports:
                print(f'SSH service found on port(s): {ssh_ports}')
            else:
                print('No SSH services found on the open ports.')
        else:
            print('No open ports found.')
    except KeyboardInterrupt:
        print('\nScan aborted by user.')
        sys.exit(1)
    except Exception as e:
        print(f'An error occurred: {e}')
        sys.exit(1)

if __name__ == '__main__':
    main()
