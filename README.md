# EmuOCPP

## Introduction

Welcome to the repository for the Open Charge Point Protocol (OCPP) emulator!
The goal of this project is to provide an extensive and flexible OCPP emulator based
on [mininet](https://mininet.org/) and
[ipmininet](https://github.com/cnp3/ipmininet),

The OCPP standard protocol facilitates communication between central
management systems (CSM)s and electric vehicle charging stations (EVCS)s. With
the increasing global usage of electric vehicles (EV)s, there is a growing need for
trustworthy testing and simulation tools.

This implementation OCPP versions **2.0.1**, **2.0** and **1.6** and OCPP
security profiles **1, 2, 3**.

It has been tested on a Ubuntu 24.04.1 LTS running on a VMware Virtual Machine and Python 3.12.3.

> **Related Tool:** For packet inspection and compliance validation, see [CheckOCPP](https://github.com/vfg27/CheckOCPP) — a Wireshark dissector for OCPP traffic. Together, **EmuOCPP** and **CheckOCPP** provide a complete toolkit for simulating, analyzing, and validating OCPP communications.

## Features

* The emulation supports **OCPP Security Profile 1**, **OCPP Security Profile 2** and **OCPP Security Profile 3**. However, it can also be used without any Security Profile.
* The emulation supports **OCPP v1.6**, **OCPP v2.0** and **OCPP v2.0.1**. However, version 1.6 doesn't support transactions.
* The emulator supports three modes of operation (allow_multiple_serial_numbers): 0 (No) | 1 (Yes) | 2 (No, but allows to steal)
* It includes a script to generate custom certificates for clients and servers.

## Configuration and Installation

To get started with the OCPP Simulator, follow these steps:
1. **Clone the Repository**: Clone this repository to your local machine using the following command:
```
git clone https://github.com/vfg27/EmuOCPP.git
```
2. Install the virtual environment (it can also be used on a Windows system but you must execute the other install executable):
```
cd EmuOCPP/scripts/
bash install.sh
```
3. Replace the BootNotificationRequest schema of OCPP 2.0 libray with the one provided.
4. **Use the virtual environment installed and choose its python interpreter**
5. **Modify server_config.yaml and client_config.yaml with the configuration that you prefer (inside the charging folder)**
6. **Execute the server.py and client.py scripts**: There are also some possible attacks scripts to this implementation in the scenarios folders. You have to execute them according to the security profile chosen. You should also modify the code to make the server listen to the address of your computer/Virtual machine and the client to communicate to that address.

## IPMininet

The emulator uses **IPMininet**. For it to work you have to:
1. Install Mininet and IPmininet:
```
pip install mininet
pip install ipmininet
```
2. Create a topology with the graphical interface:
```
python3 charging/ipmininet/topologies/edit.py
python3 charging/ipmininet/launch.py
```

## Wireshark Dissector

To ensure the dissector functions correctly, the required libraries must be installed, and the project (`ocpp-simulator` folder) should be located on the Desktop. If the folder is elsewhere, update the file paths in the OCPP dissector Lua files accordingly.

### Important: Choose a Dissector Setup

- **Single Dissector**: Use `ocppDissector.lua` to dissect OCPP packets without distinguishing between versions for some packets. One protocol added to Wireshark.
- **Separate Dissectors**: Move the three files in the `separate` folder instead. This setup provides a different dissector for each OCPP version, allowing packets from each version to be distinguished from others. Three protocols addded to Wireshark.

Then you need to move the necessary files to `/home/<USER>/.local/lib/wireshark/plugins/`. In order to do it there is a `Makefile`. To select the first option run:

```
make install-single
```
To select the second option run:

```
make install-multiple
```

Once installed, simply launch Wireshark to use the dissectors.

## Transactions

To emulate an OCPP transaction you can perform the following steps:
```
cd ocpp-simulator
```
1. Configure the client and the server and launch them:
```
venv/bin/python3 charging/server.py
venv/bin/python3 charging/client.py
```
2. Run the api_server:
```
venv/bin/python3 charging/api_server.py
```
3. Run the api_client and fill the data:
```
venv/bin/python3 charging/api_client.py reserve
```

We appreciate you choosing this OCPP Simulator to meet your needs for simulation and testing. Savor the smooth charging process! :)
