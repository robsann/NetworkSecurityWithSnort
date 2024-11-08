# Network Security with Snort (IDS/IPS)

This guide offers detailed, step-by-step instructions for setting up a virtual environment in VirtualBox to test the Snort network security tool. It covers the creation of both an Ubuntu Server VM and a Debian VM, as well as the installation of Snort 2 on the Ubuntu Server VM. By following these instructions, users will be able to conduct network security tests on the Debian VM, with Snort monitoring the activity.


## Outline

1. [Virtual Environment Set Up](#virtual-environment)
	1. [Lab Virtual Network](#lab-virtual-network)
    2. [Host-Only Network with DHCP Server Configuration](#host-only-network)
2. [Virtual Machine Installation](#vms-installation)
	1. [Ubuntu Server Installation](#ubuntu-server-installation)
	2. [Debian Installation](#debian-installation)


----------------------------------------------------------------------------------------------------


<h1 align="center" id="virtual-environment">Virtual Environment Set Up</h1>

## VirtualBox Installation

VirtualBox is a free and open-source virtualization software that allows users to run multiple operating systems on a single machine. It provides a platform for testing, development, and running applications in isolated environments.

To install VirtualBox, follow the instructions on the [VirtualBox Webpage](https://www.virtualbox.org/wiki/Downloads) according to your system.


<details>
<summary>
<h3 id="lab-virtual-network">Lab Virtual Network</h3>
</summary>

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

</details>

<details>
<summary>
<h3 id="host-only-network">Host-Only Network with DHCP Server Configuration</h3>
</summary>

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

</details>


----------------------------------------------------------------------------------------------------


<h1 align="center" id="vms-installation">Virtual Machine Installation</h1>

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
    5. Run the `zsh` command to enter the Z shell:
        ```bash
        $ zsh
        ```
        - If the error `command not found: ^M` on the `.zshrc` file is displayed in the terminal, run the command below to fix it:
        ```bash
        $ dos2unix -f .zshrc
        ```
        - **Note:** `^M` represents the carriage return (CR) character commonly used in Windows-style text files to indicate the end of a line.
    6. Then source the `.zshrc` file:
        ```bash
        $ source .zshrc
        ```
    7. Change the default login shell (use `echo $SHELL` to display the current login shell):
        ```bash
        $ chsh -s /bin/zsh
        ```
    8. Log out and log back into the server, then check the current login shell:
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
        2. Chose the `Folder Path`, type the `Folder Name`, check `Make Permanten` only, then click `OK` on the dialog box and `OK` on the settings window.
    2. Back on the guest's terminal, mount the directory on a folder with a name different than the `Folder Name` set previously on the VirtualBox interface:
        1. Create a directory at your user directory `~/` to be the mounting point:
            ```bash
            $ sudo mkdir /home/<username>/<shared_folder>
            ```
        2. Mount the host's shared folder with the command below to change its uid and gid to 1000:
            ```bash
            $ sudo mount -t vboxsf -o rw,uid=1000,gid=1000 <VBox_folder_name> /home/<username>/<shared_folder>
            ```
        - Replace `<VBox_folder_name>` by the `Folder Name` set on the VirtualBox interface, `<username>` by your username, and `<shared_folder>` by the name you wish.
    3. To make this permanent, let's set to mount the shared directory on startup.
        1. Edit the `fstab` file in the `/etc` directory:
            ```bash
            $ sudo nano /etc/fstab
            ```
            - At the end of the file, add the line below using the tab to separate the fields and replacing `<shared_host>`, `<username>`, and `<shared_folder` by their respective values:
            ```bash
            <VBox_folder_name>	/home/<username>/<shared_folder>	vboxsf	defaults	0	0
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


## Debian Installation

Download the `Debian 12.x.x amd64` disk image (ISO) from [here](https://cdimage.debian.org/debian-cd/), then follow the steps below.


<!---------- Step 1: Create a New Virtual Machine (VM) ---------->
<details>
<summary>
<h3>Step 1: Create a New Virtual Machine (VM)</h3>
</summary>

Open the `VirtualBox Manager`, then click on `New`.

1. On `Virtual machine Name and operating system`, set:
    - `Name:` Debian (Web Server)
    - `Machine Folder:` (Select the location to install the VM)
    - `ISO Image:` (Leave \<not selected\> to make a manual installation)
    - `Type:` Linux
    - `Version:` Debian (64-bit)
    - Click `Next`.
2. On `Hardware`, set:
    - `Base Memory:` 2048 MB (or more)
    - `Processors:` 1 (or more)
    - Click `Next`.
3. On `Virtual Hard disk`, set:
    - Select `Create a Virtual Hard Disk Now`
    - `Disk Size:` 20 GB (or more)
    - Click `Next`.
4. On `Summary`:
    - Review and click `Finish`

</details>


<!---------- Step 2: Fine Tune the (VM) ---------->
<details>
<summary>
<h3>Step 2: Fine Tune the (VM)</h3>
</summary>

On `VirtualBox Manager`, click on `Settings`.

1. On `General` > `Advanced`, set:
    - `Shared Clipboard:` Bidirectional
    - `Drag'n'Drop:` Bidirectional
2. On `Storage`:
    - Click on `Controller: IDE` > `Empty`.
    - Then click on the `blue disk` under `Attributes` at the right side, click `Choose a disk file...`, and select the `image file`.
3. On `Network` > `Adapter 1` (enp0s3), set:
    - Check `Enable Network Adapter`.
    - `Attacket to:` NAT
4. On `Network` > `Adapter 2` (enp0s8), set:
    - Check `Enable Network Adapter`.
    - `Attached to:` Host-only Adapter
    - `Name:` vboxnet1
5. Then click `OK` to finish.

</details>


<!---------- Step 3: Install Debian CLI ---------->
<details>
<summary>
<h3>Step 3: Install Debian CLI</h3>
</summary>

On `VirtualBox Manager`, click on `Sart`.

1. When the Debian installer menu appears, select `Install` to start the installation process.
2. Select `language`.
3. Select `your location`.
4. On `Configure the keyboard`, select `keymap` to use.
5. On `Configure the network`, select `enp0s3` interface, create a `hostname` and `domain name`.
6. On `Set up users and password`, define the `password` of the `root account`.
7. On `Set up users and password`, set the `user name`, `username`, and `password` of the `new user`.
8. On `Partition disks` chose `Guided - use entire disk`, select the `partition`, and `partition scheme`. Then hit enter on `Finish partitioning and write changes to disk` to apply the configurations.
9. On `Configure the package manager`, hit enter on `No`, select the `mirror country`, and the `Debian archive mirror`. Then leave `HTTP proxy information` empty and hit enter on `Continue` to start the installation.
12. On `Software selection` select only `web server`, `SSH server`, and `standard system utilities`, then hit Enter on `Continue`.
13. On `Configuring grup-pc`, select `Yes` to install the GRUB boot loader, then select the `/dev/sda` device for the boot loader installation.
14. On `Finish the installation`, hit `Continue` to finish the installation.

</details>


<!---------- Step 4: Final Adjustments ---------->
<details>
<summary>
<h3>Step 4: Final Adjustments</h3>
</summary>

After rebooting `log in` with your credentials.

1. First, add the `sbin` folders to the `$PATH` environment variable by adding the command below at the end of the `.profile` file in the user account folder:
    ```bash
    $ nano /home/<username>/.profile
    ```
    - Add the line below at the end of the file:
    ```bash
    export PATH=$PAHT:/usr/local/sbin:/usr/sbin:/sbin
    ```
2. Now log into the root account and `update the system`:
    ```bash
    $ su -
    \# apt update && apt upgrade
    ```
3. Install the `sudo package`, add your user account to the `sudo group`, and `reboot` the system:
    ```bash
    \# apt install sudo
    \# usermod -aG sudo <username>
    \# reboot
    ```
4. Install helpful `network and other packages`:
    ```bash
    $ sudo apt install net-tools network-manager netplan.io systemd-resolved git
    ```
4. Set the `static IP address` to the Host-only Interface (`enp0s8`):
    1. Unmask and enable network services:
        ```bash
        $ sudo systemctl unmask systemd-networkd.service
        $ sudo systemctl unmask systemd-resolved.service
        $ sudo systemctl enable systemd-networkd.service
        $ sudo systemctl mask networking
        $ sudo systemctl enable systemd-resolved.service
        ```
    2. Migrate to Netplan.io:
        ```bash
        $ sudo ENABLE_TEST_COMMANDS=1 netplan migrate && sudo netplan try
        ```
        - Press `Enter` to save the changes.
    3. Fix the permissions for the created netplan file:
        ```bash
        $ sudo chmod 600 /etc/netplan/*
        ```
    4. Open the netplan .yaml file to set the static IP address:
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
              addresses: [192.168.57.4/24]
          version: 2
        ```
    5. Reboot the system, then check the IP address:
        ```bash
        $ sudo reboot
        $ ifconfig
        ```
    6. (Optional) To access the VM from the Host Machine using SSH run:
		```bash
		$ ssh user@192.168.57.4
		```
6. (Optional) Improve shell with zshell:
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
    6. Change the default login shell (use `echo $SHELL` to display the current login shell):
        ```bash
        $ chsh -s /bin/zsh
        ```
    6. Log out and log back into the server, then check the current login shell:
        ```bash
        $ echo $SHELL
        ```
7. Install Guest Additions:
    1. On the VM menu click on `Device` > `Insert Guest Additions CD Image...`.
    2. Mount the ISO image with the guest additions:
        ```bash
        $ sudo mount /dev/cdrom /media/cdrom
        ```
    3. Install guest additions:
        ```bash
        $ sudo /media/cdrom/VBoxLinuxAdditions.run
        ```
8. Configure shared folder:
    1. On the VM menu click on `Machine` > `Settings...`.
        1. Go to `Shared Folders` and click on the `blue folder with the plus sign` at the right.
        2. Chose the `Folder Path`, type the `Folder Name`, leave only `Make Permanten` checked, then click `OK`.
        3. Click `OK` to leave save the changes.
    2. Back on terminal, mount the directory on a folder with a name different than the `Folder Name` set previously:
        1. Create a directory at your user directory `~/` to be the mounting point:
            ```bash
            $ mkdir ~/shared
			```
		2. Mount the host-shared folder with the command below to have its uid and gui equal to 1000:
			```bash
            $ sudo mount -t vboxsf -o rw,uid=1000,gid=1000 <shared_host> ~/shared
            ```
        	- In this case `shared_host` is the `Folder Name` set on VirtualBox and `~/shared` is the mounting point.
	3. (TODO) To make it permanent, set to mount the shared directory on startup following the steps below:
        1. Create an script which will mount the shared folder:
            ```bash
            $ nano mount_shared.sh
            ```
            - Set to the script the content below:
            ```bash
			#!/bin/bash
            sudo mount -t vboxsf -o rw,uid=1000,gid=1000 <shared_host> ~/shared
            ```
			- Where `shared_host` is the `Folder Name` set on Virtualbox and `~/shared` is the mounting point.
        2. (TODO) Run the script on startup.
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
