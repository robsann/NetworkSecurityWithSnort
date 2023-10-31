## Network Security with Snort (IDS/IPS)

### VirtualBox Virtual Environment - Virtual Network
- **Virtual Switch** (Host-only Network - vboxnet1) - IP: 192.168.57.0/24
    - **Kali Linux** (Host/Attack) - IP: 192.168.57.1
    - **DHCP Server** - IP: 192.168.57.2
    - **Ubuntu Server VM** (NIDS - Snort)
        - Adapter 1: NAT - IP: 10.0.2.15
        - Adapter 3: Internal Network (Host-only Adapter - vboxnet1) - IP: 192.168.57.3
    - **CentOS 7 VM** (Target)
        - Adapter 1: NAT - IP: 10.0.2.15
        - Adapter 2: Internal Network (Host-only Adapter - vboxnet1) - IP: 192.168.57.4

## VirtualBox Installation
Download and install [Oracle VM VirtualBox Manager](https://www.virtualbox.org/wiki/Downloads).

## DHCP Server Configuration
1. On **Oracle VM VirtualBox Manager** window click on **Tools > Network**. Select the **Host-only Networks** tab and click on **Create** above it.
2. Select the network:
    1. On the **Adapter** tab select **Configure Adapter Manually** and set:
        - **IPv4 Address:** 192.168.57.1
        - **IPv4 Network Mask:** 255.255.255.0
        - **IPv6 Prefix Length:** 0
    2. On the **DHCP Server** tab set **Enable Server** and the following parameters:
        - **Server Address:** 192.168.57.2
        - **Server Mask:** 255.255.255.0
        - **Lower Address Bound:** 192.168.57.3
        - **Upper Address Bound:** 192.168.57.254

## Ubuntu Server 22.04 Installation on VirtualBox

### Download the Ubuntu Server Iamage
2. Download the [Ubuntu Server 22.04.2 installer ISO](https://releases.ubuntu.com/22.04.1/ubuntu-22.04.1-live-server-amd64.iso).
### Create a New Virtual Machine (VM)
3. On **VirtualBox Manager** click on **New**:
    1. **Name and operating system**
        1. Fill the fields and click **Next**.
    2. **Memory Size**:
        1. Set 4 GB or more and click **Next**.
    3. **Hard disck**:
        1. Select **Create a virtual hard disk now** and click **Create**.
    4. **Hard disk file type**:
        1. Select **VDI (VirtualBox Disk Image)** and click **Next**.
    5. **Storage on physical hard disk**:
        1. Select **Dynamically allocated** and click **Next**.
    6. **File location and size**
        1. Choose **file location**.
        2. **Disk size**: 30 GB
        3. Click on **Create**.
### Fine Tune the VM and Select OS Image
4. On **VirtualBox Manager** select the **Ubuntu Server VN** created and click on **Settings**.
    1. On **System > Processor** set 2 CPUs on **Processor(s)**.
    2. On **Storage** on **Storage Devices** click on  **Controller: IDE > Empty** then click on the disk at the right side of **Optical Drive** and and choose the downloaded **Ubuntu Server image**.
    3. On **Network > Adaptor 1**:
        1. **Attached to:** NAT
    4. On **Network > Adapter 3**:
        1. **Attached to:** Host-only Adapter
        2. **Name:** vboxnet1
        3. **Advanced > Promiscuous Mode:** Allow All
    4. Click on **OK**.
### Install Ubuntu Server
5. On **VirtualBox Manager** select the **Ubuntu Server VM** and click on **Sart**.
    1. Hit enter on **Try or Install Ubuntu Server**.
    2. Select **language**.
    3. On **Installer update available**:
        1. Select **Continue without updating**.
    4. On **Keyboard configuration**:
        1. Select **Layout** and **Variant** and hit enter on **Done**.
    5. On **Choose type of install**:
        1. Choose **Ubuntu Server** and hit enter on **Done**.
    6. On **Network connections**:
        1. `enp0s3 DHCPv4` should be `eth 10.0.2.15/24`.
        2. `enp0s9 DHCPv4` should be `eth 192.168.57.3/24`.
        3. Hit enter on **Done**.
    7. On **Configure proxy** just hit enter on **Done**.
    8. On **Configure Ubuntu archive mirror** just hit enter on **Done**.
    9. On **Guided storage configuration** just leave default and hit enter on **Done**.
    10. On **Storage configuration** just hit enter on **Done**.
        1. On the message box **Confirm destructive action** click on **Continue**.
    11. On **Profile setup** fill the fields ant press enter on **Done**.
    12. On **Upgrade to Ubuntu Pro** select **Skip for now** and hit enter on **Continue**.
    13. On **SSH Setup** select **Install OpenSSH server** and hit enter on **Done**.
    14. On **Featured Server Snaps** just press enter on **Done** and the installation will     .
    15. On **Install complete!** hit enter on **Cancel update and reboot**, it will take a while to reboot.
    16. On **Please remove the installation medium** just hit **ENTER** and it will reboot.


## NIDS/NIPS Snort Setup in Ubuntu Server 22.04

### Installing Snort 2
Installing with apt:
```
$ sudo apt install snort
```
Checking Snort version:
```
$ snort -V
```

### Edit the configuration file:
Open configuration file:
```
$ sudo nano /etc/snort/snort.conf
```
Set protected network, line 45:
```
Ipvar HOME_NET 192.168.57.0/24
```
Set external network:
```
ipvar EXTERNAL_NET any
```
List of DNS servers on the protected network:
```
ipvar DNS_SERVERS $HOME_NET
```
List of SMTP servers on the protected network:
```
ipvar SMTP_SERVERS $HOME_NET
```
List of web servers on the protected network:
```
ipvar HTTP_SERVERS $HOME_NET
```
Set rule files' path, lines 104 to 108:
```
var RULE_PATH /etc/snort/rules
var SO_RULE_PATH /etc/snort/so_rules
var PREPROC_RULE_PATH /etc/snort/preproc_rules
var WHITE_LIST_PATH /etc/snort/rules/iplists
var BLACK_LIST_PATH /etc/snort/rules/iplists
```
Comment lines 514 and 515:
```
# var WHITE_LIST_PATH ../rules
# var BLACK_LIST_PATH ../rules
```
Comment around line 548:
```
# include $RULE_PATH/local.rules
```
To check the configuration file run:
```
$ sudo snort -T -i enp0s9 -c /etc/snort/snort.conf
```
Finish, Snort 2.9.11.1 installed on Ubuntu.

### Local Rules Configuration
Open local rules:
```
$ sudo nano /etc/snort/rules/local.rules
```
Write a rule to generate an alert message for each IP package captured:
```
alert ip any any -> any any (msg:"IP Packet detected"; sid:10000001; rev:001;)
```
Now it is possible to scan the network using the IDS mode:
```
$ sudo snort -A console -c /etc/snort/snort.conf -i enp0s9
```
Use `ping` and `tcpdump` to generate ICMP traffic date and to monitor packets, respectively.


# 1 - Nmap Scan Detection with Snort (NIDS)

**Virtual Network (Host-only Network - 192.168.57.0/24)**
- Kali Linux (Host/Attack) - IP: 192.168.57.1
- DHCP Server - IP: 192.168.57.2
- Ubuntu Server VM (NIDS Snort) - IP: 192.168.57.3
- CentOS 7 VM (FTP - SSH) - IP: 192.168.57.4

## How to identify a NMAP Ping Scan
Add the following rule to `/etc/snort/rules/local.rules` to capture the ICMP protocol sent to CentOS machine on the 192.168.1.x network:
```
alert icmp any any -> 192.168.57.4 any (msg:"NMAP ping sweep Scan"; dsize:0; sld:10000004; rev 1;)
```
On Ubuntu Server machine, start the NIDS:
```
$ snort -A console -c c:\Snort\etc\snort.conf -i enp0s9
```
On the Attack machine, open Wireshark to capture the target network traffic:
```
ip.addr == "192.168.57.4"
```
On the Attack machine, run the following command to identify if the host is up or down.
```
$ nmap -sP --disable-arp-ping 192.168.57.4
```

## How to identify a NMAP TCP Scan
Add to `/etc/snort/rules/local.rules` the following rule:
```
alert tcp any any -> 192.168.57.4 22 (msg:"NMAP TCP Scan"; sid:10000005; rev:2;)
```
On Ubuntu Server machine, start the NIDS:
```
$ snort -A console -c c:\Snort\etc\snort.conf -i enp0s9
```
On the Attack machine, open Wireshark to see the captured traffic generated by NMAP on port 22.
```
ip.addr == "192.168.57.4"
```
On the Attack machine, run the following command to perform a TCP Scan on port 22:
```
# nmap -sT -p22 192.168.57.4
```
On Ubuntu or CentOS start tcpdump:
```
tcpdump -vv -i enp0s9 port 22
```
The applied rule on the NIDS now can be validated.

## How to identify NMAP XMAS Scan
Add to `/etc/snort/rules/local.rules` the following rule:
```
alert tcp any any -> 192.168.57.4  22 (msg:"Nmap XMAS Tree Scan"; flags:FPU; sid:10000006; rev:1;)
```
On Ubuntu Server machine, start the NIDS:
```
$ snort -A console -c c:\Snort\etc\snort.conf -i enp0s9
```
On Ubuntu or CentOS start tcpdump:
```
tcpdump -vv -i enp0s9 port 22
```
On the Attack machine, open Wireshark to see the captured traffic generated by NMAP on port 22.
```
ip.addr == "192.168.57.4 "
```
On the Attack machine, run the following command to perform a XMAS Scan on port 22:
```
# nmap -sX -p22 192.168.57.4
```
The generate packets can be identified in Snort, Wireshark, and tcpdump.

## How to identify NMAP FIN Scan
Add to `/etc/snort/rules/local.rules` the following rule:
```
alert tcp any any -> 192.168.57.4  22 (msg:"Nmap FIN Scan"; flags:F; sid:10000008; rev:1;)
```
On Ubuntu Server machine, start the NIDS:
```
$ snort -A console -c c:\Snort\etc\snort.conf -i enp0s9
```
On Ubuntu or CentOS start tcpdump:
```
tcpdump -vv -i enp0s9 port 22
```
On the Attack machine, open Wireshark to see the captured traffic generated by NMAP on port 22.
```
ip.addr == "192.168.57.4 "
```
On the Attack machine, run the following command to perform a FIN Scan on port 22:
```
# nmap -sF -p22 192.168.57.4
```
The generate packets can be identified in Snort, Wireshark, and tcpdump.

## How to identify NULL Scan
Add to `/etc/snort/rules/local.rules` the following rule:
```
alert tcp any any -> 192.168.57.4  22 (msg:"Nmap NULL Scan"; flags:0; sid:10000009; rev:1;)
```
On Ubuntu Server machine, start the NIDS:
```
$ snort -A console -c c:\Snort\etc\snort.conf -i enp0s9
```
On Ubuntu or CentOS start tcpdump:
```
tcpdump -vv -i enp0s9 port 22
```
On the Attack machine, open Wireshark to see the captured traffic generated by NMAP on port 22.
```
ip.addr == "192.168.57.4 "
```
On the Attack machine, run the following command to perform a NULL Scan on port 22:
```
# nmap -sN -p22 192.168.57.4
```
The generate packets can be identified in Snort, Wireshark, and tcpdump.

## How to identify NMAP UDP Scan
Add to `/etc/snort/rules/local.rules` the following rule:
```
alert udp any any -> 192.168.57.4  any (msg:"Nmap UDP Scan"; sid:10000010; rev:1;)
```
On Ubuntu Server machine, start the NIDS:
```
$ snort -A console -c c:\Snort\etc\snort.conf -i enp0s9
```
On the Attack machine, open Wireshark to see the captured traffic generated by NMAP on port 68.
```
ip.addr == "192.168.57.4 "
```
On the Attack machine, run the following command to perform a UDP Scan on port 22:
```
# nmap -sU -p68 192.168.57.4
```
The generate packets can be identified in Snort, Wireshark, and tcpdump.


