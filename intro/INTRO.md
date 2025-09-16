# The world of Active Directory

If you have no idea what Active Directory is or how it works? Are you eager to learn how to compromise an Active Directory environment? Then you are in the right place!

## Introduction
First we need to clarify a few terms that are used in the world of Active Directory.

**Active Directory (AD)** is a directory service developed by Microsoft for Windows domain networks. It is used for managing computers and other devices on a network, providing authentication and authorization services, and enabling centralized management of resources.

You will often hear the term **"Domain"**. The domain is on the surface just a fully qualified domain name (FQDN) that is used to identify the Active Directory environment. For example, in this lab the domain is `hack.lu`. However, when talking about Active Directory, the term "domain" often refers to the Active Directory environment itself, which includes the domain controllers, users, computers, and other resources that are part of that environment.

A domain will have **Domain Controllers** (DCs). These are servers that host the Active Directory database and provide authentication and authorization services for users and computers in the domain. Usually a company will have at least two domain controllers for redundancy, but in this lab we will only have one domain controller.

In Active Directory, there multiple different built-in groups. A very important group for an attacker is the **Domain Admins** group. Members of this group have full control over the domain and can perform (nearly) any action in the Active Directory environment. Therefore, the goal of a security assessment is often to become a Domain Admin.

## Setup 🐧

There are many many tools that are used by Penetration Testers and Red Teamers. In this Introduction you will get to know in particular the following tools:
- **NetExec**: A tool that allows you to enumerate the network, execute commands on remote systems and harvest credentials.
- **impacket**: A collection of Python classes for working with network protocols with a huge set of examples for various tasks.
- **BloodHound**: A tool that allows you to visualize potential attack paths in an Active Directory environment.

### Installation 🛠️

#### Setup on Kali
- **NetExec**: If you are on Kali, NetExec should be preinstalled. 
- **impacket**: To install impacket, first [install pipx](https://pipx.pypa.io/stable/installation/#on-linux) and then use pipx to isntall the impacket scripts: `pipx install git+https://github.com/fortra/impacket`
- **BloodHound**: To install Bloodhound, follow the installation instructions [here](https://www.kali.org/tools/bloodhound/). When you are done, you should be logged in to the web interface.

If not, please install NetExec as described [here](https://www.netexec.wiki/getting-started/installation/installation-on-unix). Once you have installed NetExec with pipx, install impacket the same way using `pipx install git+https://github.com/fortra/impacket`. To install BloodHound please follow the instructions on the [BloodHound Wiki](https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart) until you are logged in to the web interface.

#### Setup on other Linux distributions
We will be using pipx to install NetExec and impacket. Pipx has the advantage that python tooling is available via command line, while pipx takes care of the env handling without polluting your system Python installation. Please install pipx with by following the instructions [here](https://pipx.pypa.io/stable/installation/#on-linux).

Once pipx is installed and set up, you can install NetExec and impacket using the following commands:
```
pipx install git+https://github.com/Pennyw0rth/NetExec
pipx install git+https://github.com/fortra/impacket
```

To install BloodHound please follow their installation instructions [here](https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart#install-bloodhound-ce). You will need [Docker](https://docs.docker.com/engine/install/) installed, as described in step 1. Once you are logged into the web ui, you are ready to go.

# Hands-on ⌨️

### 1. Enumeration 🔍
The first thing you do is always enumerate your network. Fire up nmap and take a look at the Domain Controller:

<img src="assets/nmap-dc-scan.png" alt="DC nmap scan" height="400"/>

A domain controller typically has a lot of ports open. However, especially the SMB port (445), LDAP port (389) and LDAPS port (636) are a good indicator that this is a domain controller. As also the port for Kerberos (88) and DNS (53) are open, this pretty much confirms our guess.

**SMB** or **Server Message Block** is a network file sharing protocol that is not only used for file sharing, but also for RPC or command execution. This is a very important protocol in Active Directory and the primary protocol that attackers and therefore security professionals use to interact with the domain. Usually all Windows systems in the domain will have SMB enabled. **LDAP** or **Lightweight Directory Access Protocol** is in my opinion the second most important protocol for security assessments. It is a directory service hostet on domain controllers and provides information about most objects in the domain in tree based structure. This includes users, computers, groups and much more. We can use LDAP to enumerate these objects with very low privileges, as most of the information is available to all authenticated users in the domain.

Let's use NetExec and the SMB protocol to get information the target. The basic syntax of NetExec (nxc in short) is `netexec <protocol> <target> <command>`. NetExec supports a lot of protocols, but we will focus on SMB and LDAP in this lab. First, just connect to the domain controller via SMB to see which information is available to us:

<img src="assets/smb-scan.png" alt="SMB scan" width="1150"/>

This already provides valuable information. We can see the build version `26100` which corresponds to either Windows 11 or Windows Server 2025. At the time of writing, this is the latest version of Windows Server. We can also see the target host name `DC01` and the domain name `hack.lu`. 

❗ Before we continue, we should add the hostname and domain name to our `/etc/hosts` file, so if later any tool tries to connect to the domain controller via hostname, it will resolve to the correct IP address❗
NetExec will automatically generate the entry for you with the `--generate-hosts-file` option. Run the following command to generate the hosts file and then add the line to your `/etc/hosts` file:
```bash
nxc smb <ip> --generate-hosts-file
```
If you have configured this correctly, you should be able to also use the fully qualified domain name (FQDN) `dc01.hack.lu` to connect to the domain controller:

<img src="assets/connect-to-hack-lu.png" alt="Connect to hack.lu" width="1170"/>

### 2. Using credentials
For this Lab, we will assume that a user has already been compromised and we have the credentials of this user. So here are the credentials for Donald Duck, who (un)fortunately clicked on your phishing link:
```
Username: donald.duck
Password: Daisy4Ever!
```
Let's verify these credentials by connecting to the domain controller via SMB:
```bash
nxc smb <ip> -u donald.duck -p 'Daisy4Ever!'
```
As we now have valid credentials, we should enumerate the domain and get familiar with the configuration. First, we will query the password policy to see if there are any restrictions for password brute forcing in place:

<img src="assets/pass-pol.png" alt="Password Policy" width="1140"/>

Interestingly, there is no lock out threshhold defined, which means we do not lock out accounts after a certain number of failed login attempts. As there is also a minimum password length of 7 characters, we could theoretically try to brute force other users. However, brute forcing over the network is not very efficient and will also most certainly raise alarms in any monitoring software.

Let's take a look at the SMB shares that are available to us. We can use the `--shares` option to list all shares on the domain controller:

<img src="assets/smb-shares.png" alt="SMB Shares" width="1140"/>

And indeed, there is an interesting share called `IT-Deployment`. But first, let's break down what each share is used for:
- **ADMIN\$** and **C\$**: These are administrative shares that provide access to the file system on the host. They are typically used for remote administration.
- **IPC\$**: This is the Inter-Process Communication share, which is used for remote communication between processes over named pipes.
- **NETLOGON**: This share is used for logon scripts and group policies. It is a read-only share that contains scripts and files that are executed when a user logs on to the domain.
- **SYSVOL**: This share contains files that are used for domain management, such as group policies (GPOs) and logon scripts

And now the interesting one:
- **IT-Deployment**: So far we don't have READ access, but there are likely interesting files in this share. From an attacker perspective, access to this share could either have privileged groups like Domain Admins or perhaps **computer accounts** that need the access for the deployment process.

### 3. LDAP Enumeration
Let us get more information using the LDAP protocol. 
With the commands `--users` and `--groups`, we can enumerate all users and groups in the domain. Specifying a specific group after the `--group` option will enumerate the members of that group.
Two quick commands and we get the list of all domain users and the members of the Domain Administrators group:

<img src="assets/ldap-enumeration.png" alt="LDAP Enumeration" width="1450"/>

Enumerating LDAP can pose very valuable as most of the attributes in Active Directory are world readable. Not only user and group relations are available, but also information about other Active Directory services are written to LDAP. For example if Active Directory Certificate Services (AD CS) or Microsoft Endpoint Configuration Manager (MECM, formerly SCCM) are deployed, there will be traces in LDAP.

All of this functionality are LDAP queries in the background. Therefore, you can also query all attributes manually, like this:
```bash
nxc ldap <ip> -u donald.duck -p 'Daisy4Ever!' --query "(sAMAccountName=donald.duck)" ""
```

### 4. BloodHound
Another way to query and visualize LDAP information is BloodHound. "BloodHound leverages graph theory to reveal hidden and often unintended relationships across identity and access management systems." (from the [BloodHound GitHub README](https://github.com/SpecterOps/BloodHound)). There are multiple different "collectors" with which you can collect BloodHound data. The most common two are:
- **SharpHound**: It is written in C# and can be executed on Windows systems. It collects a lot of different data, including user and group information, sessions, local admin rights, ACLs and much more. Also it is the most feature rich collector, as it is developed by the BloodHound team.
- **BloodHound.py**: A Python based collector that can be executed on Linux systems, developed by [dirk-jan](https://github.com/dirkjanm/BloodHound.py). It implements most of the functionality of SharpHound and is usually the preferred choice for Linux users.

NetExec has integrated BloodHound.py, so you can use it to collect data and directly import it into the BloodHound web interface. The command is as follows:
```bash
nxc ldap <ip> -u donald.duck -p 'Daisy4Ever!' --bloodhound -c all
```

This will result in a zip file which can be directly imported into the BloodHound web interface.

### 5. Dumping the NTDS.dit