from scapy.all import IP, TCP, sr1
import argparse
import asyncio
import nmap
import time 


class PortScanner:
    def __init__(self):
        self.target_ports = [21, 22, 23, 25, 53, 80, 110, 115, 135, 139, 143, 443, 993, 995, 3389, 1433, 1521, 3306, 5432, 5900, 8080, 8443, 9100, 1434, 1723, 27017, 5060, 8081, 69, 123, 161, 
                             389, 445, 5901, 5433, 6666, 6667, 8088, 10000, 27015, 28017, 514, 873, 1524, 2049, 8000, 8888, 9090, 143, 49152, 49153, 49154, 49155, 49156, 49157, 8082, 
                             4567, 81, 5000, 111, 7547, 28960, 27374, 29900, 18067, 4444, 1024, 7676, 30005, 1025, 5678, 20, 1027, 1026, 1050, 1029, 1028, 8594, 1863, 3783, 1002, 4664, 4]

    @staticmethod
    def craft_and_send_packet_sync(destination_ip, destination_port):
        try:
            packet = IP(dst=destination_ip) / TCP(dport=destination_port, flags="S")
            response = sr1(packet, timeout=2, verbose=0)

            if response and response.haslayer(TCP):
                if response[TCP].flags == 0x12:
                    return destination_port, "open"
                else:
                    return destination_port, "closed"
            else:
                return destination_port, "no response"
        except Exception as e:
            return destination_port, f"Error: {e}"

    @classmethod
    async def craft_and_send_packet(cls, destination_ip, destination_port):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, cls.craft_and_send_packet_sync, destination_ip, destination_port)

    @classmethod
    async def nmap_scan(cls, destination_ip, target_ports):
        try:
            nm = nmap.PortScanner()
            ports = ','.join(str(port) for port in target_ports)
            nm.scan(destination_ip, ports=ports, arguments='-sS')

            states = {}
            if destination_ip in nm.all_hosts():
                for proto in nm[destination_ip].all_protocols():
                    lport = nm[destination_ip][proto].keys()
                    for port in lport:
                        states[port] = nm[destination_ip][proto][port]['state']
            return states
        except Exception as e:
            return {}

    async def integrated_scan(self, ip_address, start_port=None, end_port=None):
        start_time = time.time()
        if start_port and end_port:
            target_ports = list(range(start_port, end_port + 1))
        else:
            target_ports = self.target_ports

        scapy_results = await asyncio.gather(
            *[self.craft_and_send_packet(ip_address, port) for port in target_ports]
        )

        nmap_results = await self.nmap_scan(ip_address, target_ports)

        for port, (scapy_port, scapy_result) in zip(target_ports, scapy_results):
            if port in nmap_results and scapy_result == nmap_results[port] and scapy_result == "open":
                print(f"Port {port} is {scapy_result} (Agreed by both tools)")
        elapsed_time = time.time() - start_time
        print(f"Time taken: {elapsed_time} seconds")



def main():
    parser = argparse.ArgumentParser(description="Port scanning tool")
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("--from-port", type=int, help="Starting port for range scanning")
    parser.add_argument("--to-port", type=int, help="Ending port for range scanning")
    parser.add_argument("--scan", action="store_true", help="Scan ports from predefined list only")

    args = parser.parse_args()
    target_ip = args.ip
    start_port = args.from_port
    end_port = args.to_port

    port_scanner = PortScanner()

    if args.scan:
        asyncio.run(port_scanner.integrated_scan(target_ip)) # python mian.py 188.114.97.11 --scan 
    else:
        asyncio.run(port_scanner.integrated_scan(target_ip, start_port, end_port)) # python main.py 188.114.97.11 --from-port 80 --to-port 443


if __name__ == "__main__":
    main()