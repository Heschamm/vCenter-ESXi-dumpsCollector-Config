#!/usr/bin/env python3

import subprocess
import socket
import getpass
import os
import sys
from datetime import datetime

# Color codes
RED = '\033[0;91m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
CYAN = '\033[1;36m'
NC = '\033[0m'

def run_command(cmd, shell=True):
    """Execute a command and return output"""
    try:
        result = subprocess.run(cmd, shell=shell, capture_output=True, text=True)
        return result.stdout.strip(), result.returncode
    except Exception as e:
        return str(e), 1

def print_section(title):
    """Print section headers"""
    print(f"\n{YELLOW}=== {title} ==={NC}")

def print_subsection(title):
    """Print subsection headers"""
    print(f"\n--- {title} ---")

def get_vcenter_info():
    """Get vCenter FQDN and IP with better IP detection"""
    vc_fqdn = socket.getfqdn()
    
    # Multiple methods to get IP address
    ip_methods = []
    
    # Method 1: Using socket.gethostbyname (most reliable)
    try:
        ip = socket.gethostbyname(vc_fqdn)
        ip_methods.append(ip)
    except:
        pass
    
    # Method 2: Using hostname -I
    try:
        output, _ = run_command("hostname -I")
        if output:
            ips = output.split()
            if ips:
                ip_methods.append(ips[0])
    except:
        pass
    
    # Method 3: Using nslookup with better parsing
    try:
        nslookup_output, _ = run_command(f"nslookup {vc_fqdn}")
        if nslookup_output:
            for line in nslookup_output.split('\n'):
                if 'Address:' in line and not line.startswith('#') and '127.0.0.1' not in line:
                    parts = line.split('Address:')
                    if len(parts) > 1:
                        ip = parts[1].strip()
                        # Filter out comments and non-IP strings
                        if ip and not ip.startswith('#') and '.' in ip and not any(x in ip for x in ['#', '53']):
                            ip_methods.append(ip)
                            break
    except:
        pass
    
    # Method 4: Using ip command
    try:
        ip_output, _ = run_command("ip addr show | grep 'inet ' | grep -v '127.0.0.1' | head -1")
        if ip_output:
            ip = ip_output.split()[1].split('/')[0]
            ip_methods.append(ip)
    except:
        pass
    
    # Choose the first valid IP that's not localhost
    vc_ip = "Unable to determine"
    for ip in ip_methods:
        if ip and ip != '127.0.0.1' and not ip.startswith('127.') and '#' not in ip:
            vc_ip = ip
            break
    
    # If still no valid IP, try one more method
    if vc_ip == "Unable to determine" and ip_methods:
        vc_ip = ip_methods[0].split('#')[0].split()[0]  # Clean up any trailing comments
    
    return vc_fqdn, vc_ip

def check_service(service_name):
    """Check service status"""
    output, returncode = run_command(f"service-control --status {service_name}")
    if "is running" in output or "Running" in output:
        return f"{GREEN}Running{NC}"
    elif "is not running" in output or "Stopped" in output:
        return f"{RED}Stopped{NC}"
    else:
        return output

def get_vpxv_hosts():
    """Query vpxv_hosts table from VCDB"""
    cmd = ["/opt/vmware/vpostgres/current/bin/psql", "-d", "VCDB", "-U", "postgres", "-t", "-c", "SELECT name FROM vpxv_hosts;"]
    output, returncode = run_command(cmd, shell=False)
    if returncode == 0 and output:
        return [host.strip() for host in output.split('\n') if host.strip()]
    return []

def get_coredump_config(host, password):
    """Get coredump network configuration from ESXi host"""
    # Use simple, proven SSH command format
    cmd = f"sshpass -p {password} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@{host} 'esxcli system coredump network get'"
    output, returncode = run_command(cmd)
    
    if returncode == 0:
        config = {}
        for line in output.split('\n'):
            if 'Enabled:' in line:
                config['enabled'] = line.split('Enabled:')[1].strip().lower()
            elif 'Network Server IP:' in line:
                config['server_ip'] = line.split('Network Server IP:')[1].strip()
            elif 'Host VNic:' in line:
                config['interface'] = line.split('Host VNic:')[1].strip()
            elif 'Network Server Port:' in line:
                config['port'] = line.split('Network Server Port:')[1].strip()
        
        return config, True
    else:
        return {}, False

def test_vmk_connectivity(host, password, vmk_interface, server_ip):
    """Test VMK connectivity using vmkping"""
    cmd = f"sshpass -p {password} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@{host} 'vmkping -c 3 -I {vmk_interface} {server_ip}'"
    output, returncode = run_command(cmd)
    
    if returncode == 0:
        # Extract ping time
        for line in output.split('\n'):
            if 'time=' in line:
                ping_time = line.split('time=')[1].split(' ')[0]
                return True, ping_time
        return True, None
    else:
        # Extract error summary
        for line in output.split('\n'):
            if any(term in line for term in ['packet loss', 'unreachable', 'failed', '100% packet loss']):
                return False, line.strip()
        return False, "Connection failed"

def configure_coredump(host, password, server_ip, vmk_interface, port):
    """Configure coredump network on ESXi host"""
    # Set coredump configuration
    cmd = f"sshpass -p {password} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@{host} 'esxcli system coredump network set --server-ip={server_ip} --interface-name={vmk_interface} --server-port={port}'"
    _, returncode = run_command(cmd)
    
    if returncode != 0:
        return False, "Failed to configure coredump network"
    
    # Enable coredump
    cmd = f"sshpass -p {password} ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@{host} 'esxcli system coredump network set --enable=true'"
    _, returncode = run_command(cmd)
    
    if returncode != 0:
        return False, "Failed to enable coredump network"
    
    return True, "Success"

def main():
    # Get vCenter information
    vc_fqdn, vc_ip = get_vcenter_info()
    
    # New header format
    print("********************************************************************************")
    print(f"{YELLOW}*** C O R E  D U M P S  C O L L E C T O R  S C R I P T  ***{NC}")
    print(f"{YELLOW}*** AUTOMATES vCenter AND ESXi COREDUMP NETWORK CONFIGURATION AND ENABLEMENT ***{NC}")
    print("********************************************************************************")
    print(f"{CYAN}Scripted and tested by HESHAM ABDELRAZEK in case of any bug or improvment ideas, please reach out via Hesham.abdelrazek@kyndryl.com{NC}")
    print("")
    print("")
    print(f"Hostname: {vc_fqdn}")
    print(f"IP Address: {vc_ip}")
    print(f"User: {getpass.getuser()}")
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("==============================================\n")
    
    # Check if running as root
    if os.geteuid() != 0:
        print(f"{YELLOW}⚠ Warning: Not running as root. Some commands may fail.{NC}")
    
    # vCenter Version
    print_section("vCenter Version")
    vpxd_output, _ = run_command("vpxd -v")
    if vpxd_output:
        print(vpxd_output)
    else:
        print(f"{RED}✗ vpxd command not available{NC}")
    
    # Service Status
    print_section("Service Status")
    services = ["vmware-vpxd", "vmware-vpostgres", "vmware-netdumper"]
    for service in services:
        print_subsection(service)
        print(check_service(service))
    
    # NetDumper Service Check
    print_section("NetDumper Service Check")
    netdumper_status = check_service("vmware-netdumper")
    if "Stopped" in netdumper_status:
        print(f"{RED}✗ vmware-netdumper service is stopped{NC}")
        print("Starting vmware-netdumper service...")
        run_command("service-control --start vmware-netdumper")
        import time
        time.sleep(1)
        status_after_start = check_service("vmware-netdumper")
        if "Running" in status_after_start:
            print(f"{GREEN}{status_after_start}{NC}")
        else:
            print(status_after_start)
    elif "Running" in netdumper_status:
        print(f"{GREEN}✓ vmware-netdumper service is running{NC}")
    else:
        print("Unable to determine vmware-netdumper service status")
        print(netdumper_status)
    
    # NetDumper Detailed Check
    print_section("NetDumper Detailed Check")
    print("Processes:")
    processes, _ = run_command("ps aux | grep -i netdumper | grep -v grep")
    print(processes if processes else "No netdumper processes found")
    
    print("\nListening ports:")
    ports, _ = run_command("netstat -tlnp | grep -i netdumper")
    print(ports if ports else "No netdumper ports found")
    
    # System Health
    print_section("System Health")
    uptime, _ = run_command("uptime")
    print(f"Uptime: {uptime}")
    
    print("\nStorage:")
    storage, _ = run_command("df -h | grep -E '(Filesystem|/storage/core)'")
    print(storage if storage else "No /storage/core filesystem found")
    
    print("\nMemory (MB):")
    memory, _ = run_command("free -m")
    print(memory if memory else "free command not available")
    
    # Query vpxv_hosts table
    print_section("Querying vpxv_hosts Table")
    hosts = get_vpxv_hosts()
    
    if hosts:
        print(f"{GREEN}✓ Successfully queried vpxv_hosts table{NC}")
        
        print_section(f"Hostnames from vpxv_hosts Table ({len(hosts)} hosts)")
        for i, host in enumerate(hosts, 1):
            print(f"  {i}. {host}")
        
        # Get passwords for ESXi hosts
        print_section("ESXi Host Root Password Input")
        print("Please enter the root password for each ESXi host (input will be hidden):")
        
        esxi_passwords = {}
        for i, host in enumerate(hosts, 1):
            print(f"\nHost {i}: {host}")
            password = getpass.getpass(f"Enter root password for {host}: ")
            esxi_passwords[host] = password
        
        # Check current coredump status
        print_section("ESXi Host Coredump Network Status (Current)")
        print("Checking current coredump network status on all hosts...")
        print()
        print(f"{'Hostname':44} | {'Status':8} | {'Server IP':15} | {'Interface':9} | {'Port':5}")
        print(f"{'-'*45}+{'-'*10}+{'-'*17}+{'-'*11}+{'-'*6}")
        
        enabled_hosts = []
        disabled_hosts = []
        unknown_hosts = []
        
        for host in hosts:
            password = esxi_passwords[host]
            config, success = get_coredump_config(host, password)
            
            display_host = host[:43]
            
            if success:
                enabled = config.get('enabled', 'N/A')
                server_ip = config.get('server_ip', 'N/A')
                interface = config.get('interface', 'N/A')
                port = config.get('port', 'N/A')
                
                if enabled == 'true':
                    enabled_hosts.append(host)
                    status_color = GREEN
                    status_text = "Enabled"
                else:
                    # Any host that is not enabled (false, or any other value) goes to disabled_hosts
                    disabled_hosts.append(host)
                    status_color = RED
                    status_text = "Disabled"
                
                print(f"{display_host:44} | {status_color}{status_text:8}{NC} | {server_ip:15} | {interface:9} | {port:5}")
            else:
                # Only hosts that we cannot connect to (authentication failures) go to unknown_hosts
                unknown_hosts.append(host)
                print(f"{display_host:44} | {RED}Failed{NC:8} | {'N/A':15} | {'N/A':9} | {'N/A':5}")
        
        # Status Summary
        print_section("Status Summary")
        print(f"{GREEN}Enabled: {len(enabled_hosts)} hosts{NC}")
        print(f"{RED}Disabled: {len(disabled_hosts)} hosts{NC}")
        print(f"{YELLOW}Unknown/Failed: {len(unknown_hosts)} hosts{NC}")
        
        # Check if all hosts failed to connect
        if len(unknown_hosts) == len(hosts) and len(enabled_hosts) == 0 and len(disabled_hosts) == 0:
            print(f"\n{RED}✗ Could not connect to any ESXi hosts. Please check the credentials and try again.{NC}")
        elif not disabled_hosts and not unknown_hosts:
            print(f"\n{GREEN}✓ All ESXi hosts already have coredump network enabled. No configuration needed.{NC}")
        elif not disabled_hosts and unknown_hosts:
            print(f"\n{RED}✗ Could not connect to {len(unknown_hosts)} ESXi hosts. Please check credentials and network connectivity.{NC}")
            if enabled_hosts:
                print(f"{GREEN}✓ The {len(enabled_hosts)} hosts that were reachable already have coredump enabled.{NC}")
        else:
            print(f"\nProceeding with configuration for {len(disabled_hosts)} disabled hosts...")
            
            # Coredump Server Configuration
            print_section("Coredump Server Configuration")
            print("Where should ESXi hosts send core dumps?")
            
            # Show current detected IP and allow manual override
            print(f"Detected vCenter IP: {vc_ip}")
            use_detected_ip = input(f"Use detected vCenter IP ({vc_ip}) as coredump server? (Y/n): ").strip().lower()
            
            if use_detected_ip == 'n':
                coredump_server_ip = input("Enter coredump server IP address: ").strip()
            else:
                coredump_server_ip = vc_ip
            
            print("\nEnter the management vmk interface for ESXi hosts.")
            print("Reference format: vmk0, vmk1, etc.")
            vmk_interface = input("VMK interface (e.g., vmk0): ").strip()
            
            use_default_port = input("Use default port 6500 for coredump? (Y/n): ").strip().lower()
            if use_default_port == 'n':
                coredump_port = input("Enter coredump server port: ").strip()
            else:
                coredump_port = "6500"
            
            print(f"\n{GREEN}Coredump configuration summary:{NC}")
            print(f"  Server IP: {coredump_server_ip}")
            print(f"  VMK Interface: {vmk_interface}")
            print(f"  Port: {coredump_port}")
            
            # Test VMK Connectivity for ALL disabled hosts (they are already confirmed reachable)
            if disabled_hosts:
                print_section("Testing VMK Connectivity")
                for host in disabled_hosts:
                    password = esxi_passwords[host]
                    print(f"\nTesting connectivity from {host}...")
                    
                    success, ping_info = test_vmk_connectivity(host, password, vmk_interface, coredump_server_ip)
                    
                    if success:
                        if ping_info:
                            print(f"{GREEN}✓ vmkping to {coredump_server_ip} via {vmk_interface} successful ({ping_info}ms){NC}")
                        else:
                            print(f"{GREEN}✓ vmkping to {coredump_server_ip} via {vmk_interface} successful{NC}")
                    else:
                        print(f"{RED}✗ vmkping to {coredump_server_ip} via {vmk_interface} failed{NC}")
                        print(f"  Error: {ping_info}")
                
                # Configure ALL disabled hosts (they are already confirmed reachable)
                print_section("Configuring Disabled Hosts")
                for host in disabled_hosts:
                    password = esxi_passwords[host]
                    print(f"\n{CYAN}=== {host} ==={NC}")
                    
                    print("Configuring coredump network on host...")
                    
                    success, message = configure_coredump(host, password, coredump_server_ip, vmk_interface, coredump_port)
                    
                    if success:
                        print(f"{GREEN}✓ Configuration completed successfully{NC}")
                        
                        print("Verifying new configuration...")
                        new_config, config_success = get_coredump_config(host, password)
                        
                        if config_success and new_config.get('enabled') == 'true':
                            print(f"{GREEN}✓ Success: Coredump network is now enabled on {host}{NC}")
                            print(f"  Enabled: {new_config.get('enabled', 'N/A')}")
                            print(f"  Network Server IP: {new_config.get('server_ip', 'N/A')}")
                            print(f"  Host VNic: {new_config.get('interface', 'N/A')}")
                            print(f"  Network Server Port: {new_config.get('port', 'N/A')}")
                        else:
                            print(f"{RED}✗ Warning: Configuration completed but status still shows disabled{NC}")
                    else:
                        print(f"{RED}✗ {message}{NC}")
            
            # Final status check for ALL hosts (enabled, disabled, and unknown)
            print_section("Final Status Check")
            print()
            print(f"{'Hostname':44} | {'Status':8} | {'Server IP':15} | {'Interface':9} | {'Port':5}")
            print(f"{'-'*45}+{'-'*10}+{'-'*17}+{'-'*11}+{'-'*6}")
            
            # Check all hosts again for final status
            for host in hosts:
                password = esxi_passwords[host]
                config, success = get_coredump_config(host, password)
                
                display_host = host[:43]
                
                if success:
                    enabled = config.get('enabled', 'N/A')
                    server_ip = config.get('server_ip', 'N/A')
                    interface = config.get('interface', 'N/A')
                    port = config.get('port', 'N/A')
                    
                    if enabled == 'true':
                        status_color = GREEN
                        status_text = "Enabled"
                    else:
                        status_color = RED
                        status_text = "Disabled"
                    
                    print(f"{display_host:44} | {status_color}{status_text:8}{NC} | {server_ip:15} | {interface:9} | {port:5}")
                else:
                    print(f"{display_host:44} | {RED}Failed{NC:8} | {'N/A':15} | {'N/A':9} | {'N/A':5}")
    
    else:
        print(f"{RED}✗ Failed to query vpxv_hosts table or no results returned{NC}")
    
    # Summary
    print_section("Summary")
    print(f"vCenter: {vc_fqdn}")
    vpxd_version, _ = run_command("vpxd -v | head -1")
    if vpxd_version:
        print(vpxd_version)
    
    if 'hosts' in locals():
        print(f"ESXi hosts processed: {len(hosts)}")
        if 'enabled_hosts' in locals():
            print(f"Hosts already enabled: {len(enabled_hosts)}")
        if 'disabled_hosts' in locals():
            print(f"Hosts configured: {len(disabled_hosts)}")
        if 'unknown_hosts' in locals() and unknown_hosts:
            print(f"{RED}Hosts with connection issues: {len(unknown_hosts)}{NC}")
    
    print_section("Useful Commands")
    print("NetDumper control:")
    print("  service-control --start vmware-netdumper")
    print("  service-control --stop vmware-netdumper")
    print("  service-control --restart vmware-netdumper")
    
    print(f"\n{GREEN}✓ Script completed successfully{NC}")

if __name__ == "__main__":
    main()