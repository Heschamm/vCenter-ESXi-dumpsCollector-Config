# vCenter-ESXi-dumpsCollector-Config

DUMPs COLLECTOR SCRIPT
=====================
A Python automation tool for configuring network coredump on VMware vCenter and ESXi hosts.

DESCRIPTION
-----------
This script automates network coredump configuration across all ESXi hosts managed by vCenter. 
It discovers hosts, checks current status, tests network connectivity, and enables coredump 
with user-defined parameters.

FEATURES
--------
- Automatic ESXi host discovery from vCenter database
- Current coredump configuration status check
- VMK interface connectivity testing
- Batch configuration of multiple hosts
- Comprehensive color-coded status reporting
- Authentication failure handling

PREREQUISITES
-------------
- vCenter Server Appliance (VCSA) 6.5+
- Python 3.x
- Root access to vCenter
- sshpass utility installed
- ESXi root passwords for all hosts
- Network connectivity between ESXi and coredump server

INSTALLATION
------------
1. Upload script to vCenter Server Appliance
2. Ensure execute permissions:
   $ chmod +x dumpsCollector.py
3. Run using Python command
   $ python dumpsCollector.py

USAGE
-----
1. SSH to vCenter as root
2. Run: $ python dumpsCollector.py in the directory where the script is saved.
3. Follow interactive prompts for:
   - ESXi host root passwords
   - Coredump server IP (default: vCenter IP)
   - VMK interface (e.g., vmk0, vmk1)
   - Port (default: 6500)

SCRIPT WORKFLOW
---------------
1. vCenter System Check
   - Version detection
   - Service status (vpxd, vpostgres, netdumper)
   - System health monitoring

2. Host Discovery & Status
   - Query for all ESXi hosts
   - Check current coredump configuration
   - Categorize hosts as Enabled/Disabled/Unknown(in case of no connection to the ESXi host)

3. Configuration Phase
   - Collect user parameters
   - Test VMK connectivity
   - Configure and enable coredump on disabled hosts
   - Verify configuration success

4. Reporting
   - Final status table for all hosts
   - Configuration summary
   - Success/failure reporting

OUTPUT
------
- Color-coded status indicators
- Detailed configuration tables
- Connectivity test results
- Action summary with counts

SUPPORTED CONFIGURATIONS
------------------------
- vCenter Server Appliance 6.5, 6.7, 7.0, 8.0
- ESXi 6.5 and later
- Customizable server IP, port, and VMK interface

TROUBLESHOOTING
---------------
Common issues:
- "Permission denied": Verify ESXi root passwords
- "Connection refused": Check ESXi SSH service
- "Command not found": Install sshpass package

SECURITY NOTES
--------------
- ESXi passwords entered interactively (not stored)
- SSH connections use StrictHostKeyChecking=no

CONTACT & SUPPORT
-----------------
Scripted and tested by HESHAM ABDELRAZEK
For bug reports or improvement suggestions:
Hesham.abdelrazek@kyndryl.com

LICENSE
-------
Provided as-is without warranty.
Test in your environment before production use.

VERSION
-------
v1.0 - Complete coredump automation with Python
