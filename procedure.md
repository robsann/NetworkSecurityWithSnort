# Network Security with Snort (IDS/IPS)

This guide offers detailed, step-by-step instructions for setting up a virtual environment in VirtualBox. It covers the creation of both an Ubuntu Server VM and a CentOS 7 VM, as well as the installation of Snort 2 on the Ubuntu Server VM. By following these instructions, users will be able to conduct network security tests on the CentOS 7 VM, with Snort monitoring the activity.


## Outline

1. [Virtual Environment Set Up](#virtual-environment)
	1. [VirtualBox Set Up](#virtualbox-set-up)
2. [Virtual Machine and Tools Installation](#vm-tools-install)
	1. [Ubuntu Server Installation](#ubuntu-server-installation)
	2. [CentOS 7 Installation](#centos-7-installation)
	3. [NIDS/NIPS Snort 2 Setup on Ubuntu Server](#nidsnips-snort-setup-in-ubuntu-server)
3. [Test Scenarios](#test-scenarios)
	1. [Nmap Scan Detection with Snort](#nmap-scan-detection-with-snort)
	2. [SQL Injection Detection with Snort](#)
	3. [Backdoor Attacks Detection with Snort](#)
	4. [Rogue DHCP & Routing Attacks Detection with Snort](#)
	5. [ICMP Redirect Attack Detection with Snort](#)


----------------------------------------------------------------------------------------------------


<h1 align="center" id="virtual-environment">Virtual Environment Set Up</h1>

## VirtualBox Installation

VirtualBox is a free and open-source virtualization software that allows users to run multiple operating systems on a single machine. It provides a platform for testing, development, and running applications in isolated environments.

To install VirtualBox, follow the instructions on the [VirtualBox Webpage](https://www.virtualbox.org/wiki/Downloads) according to your system.


<details>
<summary>
<h3>Lab Virtual Network</h3>
</summary>
<span style="color:gray">

In this lab, we will be setting up a virtual network on VirtualBox. The network will consist of the components below, each with their own assigned IP addresses:

- **Virtual Switch** (vboxnet1) - 192.168.57.0/24
    - **Kali Linux** (Host/Attack) - 192.168.57.1
    - **DHCP Server** - 192.168.57.2
    - **Ubuntu Server VM** (NIDS - Snort)
        - **Adapter 1:** NAT - 10.0.2.15
        - **Adapter 3:** Host-Only Network (vboxnet1) - 192.168.57.3
    - **CentOS 7 VM** (Target)
        - **Adapter 1:** NAT - 10.0.2.15
        - **Adapter 2:** Host-Only Network (vboxnet1) - IP: 192.168.57.4

**Host-Only Network:** A Host-Only Network on VirtualBox allows virtual machines to communicate with each other and the host machine, but they are isolated from the host's network and the internet. This provides a secure environment for testing and development without the risk of exposing the host machine to potential security threats.

**NAT Adapter:** The NAT (Network Address Translation) adapter on VirtualBox allows each virtual machine to have its own isolated network with access only to the host machine and the internet, but no communication with other virtual machines.

</span>
</details>

<details>
<summary>
<h3>Host-Only Network with DHCP Server Configuration</h3>
</summary>
<span style="color:gray">

1. On the **Oracle VM VirtualBox Manager** window, click on **Tools > Network**. Select the **Host-only Networks** tab and click on **Create** above it.
2. Select the network:
    1. On the **Adapter** tab, select **Configure Adapter Manually** and set:
        - **IPv4 Address:** 192.168.57.1
        - **IPv4 Network Mask:** 255.255.255.0
        - **IPv6 Prefix Length:** 0
    2. On the **DHCP Server** tab, set **Enable Server** and the following parameters:
        - **Server Address:** 192.168.57.2
        - **Server Mask:** 255.255.255.0
        - **Lower Address Bound:** 192.168.57.3
        - **Upper Address Bound:** 192.168.57.254

</span>
</details>


----------------------------------------------------------------------------------------------------


<h1 align="center" id="vm-tools-install">Virtual Machine and Tools Installation</h1>

## Ubuntu Server Installation

Download the `Ubuntu Server 22.04.x LTS` disk image (ISO) from [here](https://cdimage.ubuntu.com/ubuntu-server/jammy/daily-live/current/), then follow the steps bellow.


<!---------- Step 1: Create a New Virtual Machine (VM) ---------->
<details>
	<summary>
		<h3>Step 1: Create a New Virtual Machine (VM)</h3>
	</summary>

Open `VirtualBox Manager` and click on `New`.
1. On `Virtual machine Name and operating system`, set:
    - `Name:` Ubuntu Server (Snort)
    - `Machine Folder:` (Select the location to install the VM)
    - `ISO Image:` (Leave \<not selected\>)
    - `Type:` Linux
    - `Version:` Ubuntu (64-bit)
    - Click `Next`.
2. On `Hardware`, set:
    - `Base Memory:` 4096 MB (or more)
    - `Processors:` 2 (or more)
    - Click `Next`.
3. On `Virtual Hard disk`, set:
    - Select `Create a Virtual Hard Disk Now`
    - `Disk Size:` 30 GB (or more)
    - Click `Next`.
4. On `Summary`:
    - Review and click `Finish`.

</details>


<!---------- Step 2: Fine Tune the VM ---------->
<details>
	<summary>
		<h3>Step 2: Fine Tune the VM</h3>
	</summary>

On `VirtualBox Manager`, select the created VM and click on `Settings`.
1. On `General` > `Advanced`, set:
    - `Shared Clipboard:` Bidirectional
    - `Drag'n'Drop:` Bidirectional
2. On `Storage`:
    - Click on `Controller: IDE` > `Empty`.
    - Then click on the `blue disk` under `Attributes` at the right side, click `Choose a disk file...`, and select the `Ubuntu Server image file`.
3. On `Network` > `Adapter 1` (enp0s3), set:
    - Check `Enable Network Adapter`.
    - `Attacket to:` NAT
4. On `Network` > `Adapter 2` (enp0s8), set:
    - Check `Enable Network Adapter`.
    - `Attached to:` Host-only Adapter
    - `Name:` vboxnet1
5. Then click `OK` to finish.

</details>


<!---------- Step 3: Install Ubuntu Server ---------->
<details>
	<summary>
		<h3>Step 3: Install Ubuntu Server</h3>
	</summary>

On `VirtualBox Manager`, click on `Sart`.
1. Hit Enter on `Try or install Ubuntu Server`.
2. Select the `language`.
3. On `Installer update available`, hit Enter on `Continue without updating`.
4. On `Keyboard configuration`, select the `Layout` and the `Variant`, then hit Enter on `Done`.
5. On `Choose type of install`, leave `Ubuntu Server` selected and hit Enter on `Done`.
6. On `Network connections`, just check the IP addresses and hit Enter on `Done`.
7. On `Configure proxy`, leave it empty and hit Enter on `Done`.
8. On `Configure Ubuntu archive mirror`, just hit Enter on `Done`.
9. On `Guided storage configuration`, leave the default and hit Enter on `Done`.
10. On `Storage configuration`, just hit Enter on `Done`.
    - On the message box `Confirm destructive action` hit Enter on `Continue`.
11. On `Profile setup`, fill up the fields ant hit Enter on `Done`.
12. On `Upgrade to Ubuntu Pro`, select `Skip for now` and hit Enter on `Continue`.
13. On `SSH Setup`, select `Install OpenSSH server`, then hit Enter on `Done`.
14. On `Featured Server Snaps`, just hit Enter on `Done` and the installation will begin.
14. On `Install complete!`, hit Enter on `Cancel update and reboot`. It will take some time to `reboot`.
15. Remove the installation medium if needed on `Devices` > `Optical Drives`, then press `ENTER`.

</details>


<!---------- Step 4: Final Adjustments ---------->
<details>
<summary>
<h3>Step 4: Final Adjustments</h3>
</summary>

After rebooting `log in` with your credentials.

1. `Update` the system:
    ```bash
    $ sudo apt update && sudo apt upgrade -y
    ```
2. Install helpful `network and other packages`:
    ```bash
    $ sudo apt install net-tools network-manager ntpdate jq
    ```
3. Update `date and time` if needed:
    ```bash
    $ date
    $ sudo ntpdate time.nist.gov
    ```
4. Set the `static IP address` to the Host-only Interface (`enp0s8`):
    1. Open the netplan .yaml file:
        ```bash
        $ sudo nano /etc/netplan/*yaml
        ```
        - Set the following parameters:
        ```yml
        network:
          ethernets:
            enp0s3:
              dhcp4: true
            enp0s8:
              dhcp4: no
              addresses: [192.168.57.3/24]
          version: 2
        ```
    2. Apply the netplan changes, restart the NetworkManager, and check the `enp0s8` interface IP address:
        ```bash
        $ sudo netplan apply
        $ sudo systemctl restart NetworkManager
        $ ifconfig
        ```
	3. (Optional) To access the VM from the Host Machine using SSH, run the command below from the host machine:
        ```bash
        $ ssh user@192.168.57.3
        ```
5. (Optional) Improve shell with `zshell`:
    1. Install zsh:
        ```bash
        $ sudo apt install zsh
        ```
    2. Install zshell plugins:
        ```bash
        $ sudo apt install zsh-syntax-highlighting zsh-autosuggestions
        ```
    3. Install fonts, qterminal, gnome-tweaks, and dos2unix:
        ```bash
        $ sudo apt install qterminal fonts-firacode gnome-tweaks dos2unix
        ```
    4. Use the command below to copy the content of `.zshrc` from [here](https://pastebin.com/rhrWSiaL) to the `~/.zshrc` file.
        ```bash
        $ wget -qO ~/.zshrc https://pastebin.com/raw/rhrWSiaL
        ```
    5. Run the `zsh` command to enter the Z shell, run the `dos2unix` command to fix the error `command not found: ^M` on the `.zshrc` file if any, then source the `.zshrc` file:
        ```bash
        $ zsh
        $ dos2unix -f .zshrc
        $ source .zshrc
        ```
        - **Note:** `^M` represents the carriage return (CR) character commonly used in Windows-style text files to indicate the end of a line.
    6. Change the default login shell (use `echo $SHELL` to display the current login shell):
        ```bash
        $ chsh -s /bin/zsh
        ```
    6. Log out and log back into the server, then check the current login shell:
        ```bash
        $ echo $SHELL
        ```
6. Install `Guest Additions`:
    1. On the VM menu click on `Device` > `Insert Guest Additions CD Image...`.
    2. Create the `/media/cdrom` folder and mount the ISO image with the guest additions:
        ```bash
        $ sudo mkdir /media/cdrom
        $ sudo mount /dev/cdrom /media/cdrom
        ```
    3. Install the dependencies for VirtualBox guest additions:
        ```bash
        $ sudo apt update
        $ sudo apt install -y build-essential linux-headers-`uname -r`
        ```
    4. Install guest additions and reboot the VM:
        ```bash
        $ sudo /media/cdrom/VBoxLinuxAdditions.run
        $ sudo shutdown -r now
        ```
7. Configure `VirtualBox shared folder`:
    1. On the VM top menu, click on `Machine` > `Settings...`.
        1. Go to `Shared Folders` and click on the `blue folder with the plus sign` at the right.
        2. Chose the `Folder Path`, type the `Folder Name`, and check `Make Permanten` only.
    2. Back on the guest's terminal, mount the directory on a folder with a name different than the `Folder Name` set previously on the VirtualBox interface:
        1. Create a directory at your user directory `~/` to be the mounting point:
            ```bash
            $ sudo mkdir /home/<username>/shared
            ```
        2. Mount the host's shared folder with the command below to change its uid and gid to 1000:
            ```bash
            $ sudo mount -t vboxsf -o rw,uid=1000,gid=1000 <shared_host> /home/<username>/shared
            ```
        - Replace `<shared_host>` by the `Folder Name` set on the VirtualBox interface and `<username>` by your username.
    3. To make this permanent, let's set to mount the shared directory on startup.
        1. Edit the `fstab` file in the `/etc` directory:
            ```bash
            $ sudo nano /etc/fstab
            ```
            - At the end of the file, add the line below using the tab to separate the fields and replace <shared_host> with `Folder Name` defined earlier and save:
            ```bash
            <shared_host>	/home/<username>/shared	vboxsf	defaults	0	0
            ```
        2. Edit `modules`:
            ```bash
            $ sudo nano /etc/modules
            ```
            - At the end of the file, add the following line and save:
            ```bash
            vboxsf
            ```
        3. After rebooting the VM, the VirtualBox shared folder should mount automatically:
        	```bash
        	$ sudo shutdown -r now
        	```

</details>


<!---------- Step 5: Create a Snapshot ---------->
<details>
	<summary>
		<h3>Step 5: Create a Snapshot</h3>
	</summary>

On the VM top menu, go to `Machine` > `Take a Snapshot...`, enter the snapshot name and description, then click `OK`.

</details>


## CentOS 7 Installation

Download the **CentOS 7 (Minimal 2009)** disk image (ISO) from [here](http://isoredirect.centos.org/centos/7/isos/x86_64/), then follow the steps bellow.

<!---------- Step 1: Create a New Virtual Machine (VM) ---------->
<details>
	<summary>
		<h3>Step 1: Create a New Virtual Machine (VM)</h3>
	</summary>

On VirtualBox Manager, click on **New**.
1. On **Virtual machine Name and operating system**, set:
    - **Name:** CentOS 7 (Web Server)
    - **Machine Folder:** /home/username/VirtualBox VMs
    - **ISO Image:** (Leave empty to make a manual installation)
    - **Type:** Linux
    - **Version:** Red Hat (64-bit)
    - Click **Next**.
2. On **Hardware**, set:
    - **Base Memory:** 4096 MB
    - **Processors:** 2
    - Click **Next**.
3. On **Virtual Hard disk**, set:
    - Select **Create a Virtual Hard Disk Now**
    - **Disk Size:** 20 GB
    - Click **Next**.
4. On **Summary**:
    - Review and click **Finish**

</details>

<!---------- Step 2: Fine Tune the VM ---------->
<details>
	<summary>
		<h3>Step 2: Fine Tune the VM</h3>
	</summary>

On VirtualBox Manager, click on **Settings**.
1. On **General** > **Advanced**, set:
    - **Shared Clipboard:** Bidirectional
    - **Drag'n'Drop:** Bidirectional
2. On **Storage**:
    - Click on **Controller: IDE** > **Empty**.
    - Then click in the **blue disk** under **Attributes** on the right side, click on **Choose a disk file...**, and select the **image file**.
2. On **Network** > **Adapter 1** (enp0s3), set:
    - Check **Enable Network Adapter**.
    - **Attacket to:** NAT
    - On **Advanced** click on **Port Forwarding**.
    - On **Port Forwarding Rules** set the following rules to access the virtual machine from the host using **SSH**.
      ```
      Name  Protocol  Host IP     Host Port   Guest IP    Guest Port
      SSH   TCP       127.0.0.1   20022       10.0.2.15   22
      ```
    - Using **Port Forwarding** the connection to **HostIP:HostPort** are redirected to **GuestIP:GuestPort**.
    - Click **Ok**.
4. On **Network** > **Adapter 3** (enp0s8), set:
    - Check **Enable Network Adapter**.
    - **Attacket to:** Host-only Adapter
    - **Name:** vboxnet1
5. Then click **OK** to finish.

</details>

<!---------- Step 3: Install CentOS 7 ---------->
<details>
	<summary>
		<h3>Step 3: Install CentOS 7</h3>
	</summary>

On VirtualBox Manager, click on **Start**.

On **CentOS 7 Setup**:
1. Select **Install CentOS 7**
2. Select **language**.
3. On **SYSTEM**, click **INSTALLATION DESTINATION** and select the disk.
4. Click on **Begin installation**.
5. Set **ROOT PASSWORD** and create user at **USER CREATION**.
6. After install, click on **Reboot**.

</details>

<!---------- Step 4: Final Adjustments ---------->
<details>
<summary>
<h3>Step 4: Final Adjustments</h3>
</summary>

1. Include **user** on **sudoers**:
    1. Change to **root** account:
        ```bash
        su -
        ```
    2. Verify if the **wheel** group is **enabled**:
        1. Open the **sudoers** file (/etc/sudoers) using the **visudo**:
            ```bash
            visudo
            ```
        2. Scroll down to find the section below that grants privileges to the **wheel** group and uncomment it if commented:
            ```bash
            ## Allows people in group wheel to run all commands
            %wheel        ALL=(ALL)       ALL
            ```
    3. Add **user** to the **wheel** group:
        ```bash
        usermod -aG wheel user
        ```
    4. Test **sudo privileges** for the **user account**:
        1. Switch to the **user account** using the following command:
            ```bash
            su - user
            ```
        2. Test a command with **sudo**:
            ```bash
            sudo ls -la /root
            ```
2. Updathe the system:
    ```bash
    sudo yum update
    ```
3. Install useful network packages:
    ```bash
    sudo yum install net-tools wget bind-utils
    ```
4. Configure the **network interfaces**:
    1. Configure the network interface **enp0s3** (NAT):
        1. Open the **enp0s3 configuration file**:
            ```bash
            nano /etc/sysconfig/network-scripts/ifcfg-enp0s3
            ```
        2. Set **ONBOOT** to **yes** and save the file.
    2. Configure the network interface **enp0s9** (Host-only Network) to use a **static IP address**:
        1. Open the **enp0s9 configuration file** and set:
            ```bash
            nano /etc/sysconfig/network-scripts/ifcfg-enp0s9
                BOOTPROTO=static
                ONBOOT=yes
                IPADDR=192.168.57.4
                NETMASK=255.255.255.0
            ```
    3. **Restart** all the **network interfaces**:
        ```bash
        sudo systemctl restart network
        ```
5. (Optional) Improve shell with zshell:
    1. Install zsh:
        ```bash
        sudo yum install zsh wget git
        ```
    2. Set zsh as the default shell for root or the user of your choice:
        ```bash
        chsh -s /bin/zsh root
        ```
    3. Install oh-my-zsh:
        ```bash
        wget https://github.com/robbyrussell/oh-my-zsh/raw/master/tools/install.sh -O - | zsh
        ```
        - To uninstall oh-my-zsh type:
            ```bash
            uninstall_oh_my_zsh
            ```
    4. Copy the oh-my-zsh tamplate to `~/.zshrc` and source `.zshrc`:
        ```bash
        cp ~/.oh-my-zsh/templates/zshrc.zsh-template ~/.zshrc
        source ~/.zshrc
        ```
    5. Download the kali theme and the autosuggestions and syntax highlighting plugins:
        ```bash
        wget -O ~/.oh-my-zsh/themes/kali-like.zsh-theme https://raw.githubusercontent.com/clamy54/kali-like-zsh-theme/master/kali-like.zsh-theme
        git clone https://github.com/zsh-users/zsh-autosuggestions.git $ZSH_CUSTOM/plugins/zsh-autosuggestions
        git clone https://github.com/zsh-users/zsh-syntax-highlighting.git $ZSH_CUSTOM/plugins/zsh-syntax-highlighting
        ```
    6. On `kali-like.zsh-theme`, disable syntax highlighting and autosuggestions:
        ```bash
        nano .oh-my-zsh/themes/kali-like.zsh-theme
            USE_SYNTAX_HIGHLIGHTING=no
            USE_ZSH_AUTOSUGGESTIONS=no
        ```
    7. On `.zshrc`, enable syntax highlighting and autosuggestions:
        ```bash
        nano .zshrc
            plugins=(git zsh-autosuggestions zsh-syntax-highlighting)
        ```
    6. On `.zshrc` set `ZSH_THEME` to `kali-like` then source `.zshrc`:
        ```bash
        nano ~/.zshrc
            ZSH_THEME="kali-like"
        source ~/.zshrc
        ```

</details>

<!---------- Step 5: Create a Snapshot ---------->
<details>
	<summary>
		<h3>Step 5: Create a Snapshot</h3>
	</summary>

On the VM top menu, go to **Machine** > **Take a Snapshot...**, enter the snapshot name and description then click **OK**.

</details>

#### Notifications
- Mouse integration
- Auto capture keyboard


## NIDS/NIPS Snort 2 Setup on Ubuntu Server

<details>
<summary>
<h3>Installing Snort 2</h3>
</summary>
<span style="color:gray">

Installing with apt:
```
$ sudo apt install snort
```
Checking Snort version:
```
$ snort -V
```
</span>
</details>


<details>
<summary>
<h3>Edit the configuration file:</h3>
</summary>
<span style="color:gray">

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
To check the configuration file, run:
```
$ sudo snort -T -i enp0s9 -c /etc/snort/snort.conf
```
Finish, Snort 2.9.11.1 installed on Ubuntu.

</span>
</details>


<details>
<summary>
<h3>Local Rules Configuration</h3>
</summary>
<span style="color:gray">

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

</span>
</details>

----------------------------------------------------------------------------------------------------


<h1 align="center" id="test-scenarios">Test Scenarios</h1>

## Nmap Scan Detection with Snort

<details>
<summary>
<h3>How to identify a NMAP Ping Scan</h3>
</summary>
<span style="color:gray">

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
</span>
</details>


<details>
<summary>
<h3>How to identify a NMAP TCP Scan</h3>
</summary>
<span style="color:gray">

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

</span>
</details>


<details>
<summary>
<h3>How to identify NMAP XMAS Scan</h3>
</summary>
<span style="color:gray">

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

</span>
</details>


<details>
<summary>
<h3>How to identify NMAP FIN Scan</h3>
</summary>
<span style="color:gray">

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

</span>
</details>


<details>
<summary>
<h3>How to identify NULL Scan</h3>
</summary>
<span style="color:gray">

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

</span>
</details>


<details>
<summary>
<h3>How to identify NMAP UDP Scan</h3>
</summary>
<span style="color:gray">

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

</span>
</details>


## SQL Injection Detection with Snort (TODO)

## Backdoor Attacks Detection with Snort (TODO)

## Rogue DHCP & Routing Attacks Detection with Snort (TODO)

## ICMP Redirect Attack Detection with Snort (TODO)

