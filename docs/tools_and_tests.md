# Network Security with Snort (IDS/IPS)

This guide offers detailed, step-by-step instructions for setting up a virtual environment in VirtualBox to test the Snort network security tool. It covers the creation of both an Ubuntu Server VM and a Debian VM, as well as the installation of Snort 2 on the Ubuntu Server VM. By following these instructions, users will be able to conduct network security tests on the Debian VM, with Snort monitoring the activity.


## Outline

1. [Tools Installation](#tools-installation)
    1. [Snort 2 (NIDS) Setup on Ubuntu Server](#snort-2-nids-setup-on-ubuntu-server)
2. [Test Scenarios](#test-scenarios)
	1. [Scenario 1: Nmap Scan Detection with Snort](#scenario-1-nmap-scan-detection-with-snort)
	2. [Scenario 2: SQL Injection Detection with Snort](#)
	3. [Scenario 3: Backdoor Attacks Detection with Snort](#)
	4. [Scenario 4: Rogue DHCP & Routing Attacks Detection with Snort](#)
	5. [Scenario 5: ICMP Redirect Attack Detection with Snort](#)


----------------------------------------------------------------------------------------------------


<h1 align="center" id="tools-installation">Tools Installation</h1>

## Snort 2 (NIDS) Setup on Ubuntu Server

Snort has currently two versions available which are Snort 2 and Snort 3. Snort 3 is an updated version with a new design that offers improved efficacy, performance, scalability, and extensibility. On the other hand, Snort 2 is the most widely implemented version and provides extensive support, documentation, and rule-sets. For the purposes of this lab, we will be using Snort 2. Follow the steps below to easily install and configure it in NIDS mode.

<details>
<summary>
<h3>Step 1: Installing Snort 2</h3>
</summary>

1. Update apt package manager and install Snort 2:
    ```bash
    $ sudo apt update
    $ sudo apt install snort
    ```
    - If prompted during the installation to set the interface Snort should listen on and the address range for the local network, use `ip a` to find appropriate values.
2. Checking Snort version:
    ```bash
    $ snort -V
    ```
</details>


<details>
<summary>
<h3>Step 2: Configuring Snort 2</h3>
</summary>

1. Edit the Snort configuration file using the following values:
    - Open the Snort configuration file:
    ```bash
    $ sudo nano /etc/snort/snort.conf
    ```
    - In Step #1, set protected network and external network:
    ```yml
    # Setup the network addresses you are protecting
    #
    # Note to Debian users: this value is overriden when starting
    # up the Snort daemon through the init.d script by the
    # value of DEBIAN_SNORT_HOME_NET s defined in the
    # /etc/snort/snort.debian.conf configuration file
    #
    ipvar HOME_NET 192.168.57.0/24

    # Set up the external network addresses. Leave as "any" in most situations
    ipvar EXTERNAL_NET any
    ```
    - Set rule files' path:
    ```yml
    # Path to your rules files (this can be a relative path)
    # Note for Windows users:  You are advised to make this an absolute path,
    # such as:  c:\snort\rules
    var RULE_PATH /etc/snort/rules
    var SO_RULE_PATH /etc/snort/so_rules
    var PREPROC_RULE_PATH /etc/snort/preproc_rules

    # If you are using reputation preprocessor set these
    # Currently there is a bug with relative paths, they are relative to where snort is
    # not relative to snort.conf like the above variables
    # This is completely inconsistent with how other vars work, BUG 89986
    # Set the absolute path appropriately
    var WHITE_LIST_PATH /etc/snort/rules
    var BLACK_LIST_PATH /etc/snort/rules
    ```
    - In Step #6, uncomment the output line correspending to PCAP in order to generate logs in PCAP files for the rule-matching traffic pattern:
    ```yml
    # pcap
    output log_tcpdump: /var/log/snort/tcpdump.log
    ```
    - In Step #7, ensure that only the local rules file is left uncommented, while commenting out all other rules (community rules) in order to test Snort:
    ```yml
    include $RULE_PATH/local.rules
    ```
    - The `/etc/snort/rules/local.rules` file is where user can write their own rules for Snort.
2. Test the configuration file by running the following command:
    ```
    $ sudo snort -T -i enp0s9 -c /etc/snort/snort.conf
    ```
    - You shoud see a successfully validation message displayed on the output.

</details>


<details>
<summary>
<h3>Step 3: Local Rules Configuration</h3>
</summary>

1. Snort rules composed by two parts which are Rule Header and Rule Options.
    - Rule Header ([Rule Options]):
    ```yml
    action protocol source_ip source_port -> destination_ip destination_port ([Rule Options])
    ```
    - On Rule Options the `sid` values are divided in three categories ([reference](http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node31.html)):
        - `< 100`: Reserved for future use.
        - `100-999,999`: Rules included with the Snort distribution.
        - `>= 1,000,000`: Used for local rules.
2. Write the following rules to generate an alert message for packets used in Nmap scanning:
    - Open local rules:
    ```bash
    $ sudo nano /etc/snort/rules/local.rules
    ```
    - **IP Packets:** Rule to match all packets using the IP protocol.
    ```yml
    alert ip any any -> any any (msg:"IP Packet detected"; sid:1000000; rev:1;)
    ```
    - **ICMP Packets:** The following rules match five types of packets using the ICMP protocol.
    ```yml
    alert icmp any any <> 192.168.57.4 any (msg:"ICMP Packet detected"; sid:2000000; rev:1;)
    alert icmp any any <> 192.168.57.4 any (msg:"ICMP Echo Request";      itype:8;  sid:2000001; rev:1;)
    alert icmp any any <> 192.168.57.4 any (msg:"ICMP Echo Reply";        itype:0;  sid:2000002; rev:1;)
    alert icmp any any <> 192.168.57.4 any (msg:"ICMP Timestamp Request"; itype:13; sid:2000003; rev:1;)
    alert icmp any any <> 192.168.57.4 any (msg:"ICMP Timestamp Reply)";  itype:14; sid:2000004; rev:1;)
    alert icmp any any <> 192.168.57.4 any (msg:"ICMP Destination Unreachable"; itype:3; sid:2000005; rev:1;)
    ```
    - **TCP Packets:** The following rules match eight types of packets using the TCP protocol.
    ```yml
    alert tcp any any <> 192.168.57.4 any (msg:"TCP Packet detected"; sid:3000000; rev:1;)
    alert tcp any any <> 192.168.57.4 any (msg:"TCP SYN";       flags:S;   sid:3000001; rev:1;)
    alert tcp any any <> 192.168.57.4 any (msg:"TCP SYN/ACK";   flags:SA;  sid:3000002; rev:1;)
    alert tcp any any <> 192.168.57.4 any (msg:"TCP ACK";       flags:A;   sid:3000003; rev:1;)
    alert tcp any any <> 192.168.57.4 any (msg:"TCP RST";       flags:R;   sid:3000004; rev:1;)
    alert tcp any any <> 192.168.57.4 any (msg:"TCP RST/ACK";   flags:RA;  sid:3000005; rev:1;)
    alert tcp any any <> 192.168.57.4 any (msg:"TCP NULL";      flags:0;   sif:3000006; rev:1;)
    alert tcp any any <> 192.168.57.4 any (msg:"TCP FIN";       flags:F;   sif:3000007; rev:1;)
    alert tcp any any <> 192.168.57.4 any (msg:"TCP XMAS Tree"; flags:FPU; sif:3000008; rev:1;)
    ```
    - **UDP Packets:** Rule to match all packets using the UDP protocol.
    ```yml
    alert udp any any <> 192.168.57.4 any (msg:"UDP Packet detected"; sid:4000000; rev:1;)
    alert udp any any <> 192.168.57.4 53  (msg:"UDP DNS";  sid:4000001; rev:1;)
    alert udp any any <> 192.168.57.4 67  (msg:"UDP DHCP"; sid:4000002; rev:1;)
    alert udp any any <> 192.168.57.4 161 (msg:"UDP SNMP"; sid:4000003; rev:1;)
    ```
3. Now it is possible to scan the network using the IDS mode:
    ```bash
    $ sudo snort -A console -c /etc/snort/snort.conf -i enp0s9
    ```
5. Use `ping` and `tcpdump` to generate ICMP traffic date and to monitor packets, respectively.

</details>

----------------------------------------------------------------------------------------------------


<h1 align="center" id="test-scenarios">Test Scenarios</h1>

## Scenario 1: Nmap Scan Detection with Snort

<details>
<summary>
<h3>Test 1.1: Identifying NMAP Ping Scan</h3>
</summary>

Add the following rule to `/etc/snort/rules/local.rules` to capture the ICMP protocol sent to Debia machine on the 192.168.1.0/24 network:
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
</details>


<details>
<summary>
<h3>Test 1.2: Identifying NMAP TCP Scan</h3>
</summary>

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

</details>


<details>
<summary>
<h3>Test 1.3: Identifying NMAP XMAS Scan</h3>
</summary>

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
On the Attack machine, run the following command to perform an XMAS Scan on port 22:
```
# nmap -sX -p22 192.168.57.4
```
The generated packets can be identified in Snort, Wireshark, and tcpdump.

</details>


<details>
<summary>
<h3>Test 1.4: Identifying NMAP FIN Scan</h3>
</summary>

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
The generated packets can be identified in Snort, Wireshark, and tcpdump.

</details>


<details>
<summary>
<h3>Test 1.5: Identifying NULL Scan</h3>
</summary>

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
The generated packets can be identified in Snort, Wireshark, and tcpdump.

</details>


<details>
<summary>
<h3>Test 1.6: Identifying NMAP UDP Scan</h3>
</summary>

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
The generated packets can be identified in Snort, Wireshark, and tcpdump.

</details>


## Scenario 2: SQL Injection Detection with Snort (TODO)

## Scenario 3: Backdoor Attacks Detection with Snort (TODO)

## Scenario 4: Rogue DHCP & Routing Attacks Detection with Snort (TODO)

## Scenario 5: ICMP Redirect Attack Detection with Snort (TODO)

