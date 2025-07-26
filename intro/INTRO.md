# The world of Active Directory

If you have no idea what Active Directory is or how it works? Are you eager to learn how to compromise an Active Directory environment? Then you are in the right place!

## Introduction
First we need to clarify a few terms that are used in the world of Active Directory.

**Active Directory (AD)** is a directory service developed by Microsoft for Windows domain networks. It is used for managing computers and other devices on a network, providing authentication and authorization services, and enabling centralized management of resources.

You will often hear the term **"Domain"**. The domain is on the surface just a fully qualified domain name (FQDN) that is used to identify the Active Directory environment. For example, in this lab the domain is `hack.lu`. However, when talking about Active Directory, the term "domain" often refers to the Active Directory environment itself, which includes the domain controllers, users, computers, and other resources that are part of that environment.

A domain will have **Domain Controllers** (DCs). These are servers that host the Active Directory database and provide authentication and authorization services for users and computers in the domain. Usually a company will have at least two domain controllers for redundancy, but in this lab we will only have one domain controller.

In Active Directory, there multiple different built-in groups. A very important group for an attacker is the **Domain Admins** group. Members of this group have full control over the domain and can perform (nearly) any action in the Active Directory environment. Therefore, the goal of an security assessment is often to become Domain Admin.

## Setup

There are many many tools that are used by Penetration Testers and Red Teamers. In this Introduction you will get to know in particular the following tools:
- **NetExec**: A tool that allows you to enumerate the network, execute commands on remote systems and harvest credentials.
- **impacket**: A collection of Python classes for working with network protocols with a huge set of examples for various tasks.
- **BloodHound**: A tool that allows you to visualize potential attack paths in an Active Directory environment.

### Installation

If you are on Kali, all of the tools should already be installed. If not, please install NetExec as described [here](https://www.netexec.wiki/getting-started/installation/installation-on-unix). Once you have installed NetExec with pipx, install impacket the same way using `pipx install git+https://github.com/fortra/impacket`. To install BloodHound please follow the instructions on the [BloodHound Wiki](https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart) until you are logged in to the web interface.

# Hands-on

The first thing you do is always enumerate your network. Fire up nmap and take a look at the Domain Controller:
<screenshot>

You can see that the Domain Controller is running Windows Server 2022 and has port 445 open. This is the port used for SMB (Server Message Block) one of the most important protocols in Active Directory. As an attacker SMB is the primary protocol you will use to interact with the domain controller and other systems in the domain. Besides file access, it provides an incredible amount of functionalities. Attackers use it for login testing (or brute-forcing), remote command execution, RPC and much more.