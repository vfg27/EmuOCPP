import ast
import base64
from http import HTTPStatus
import sys
import os
sys.path.append('.')

import asyncio
import logging
import re
import time
from datetime import datetime, timedelta, timezone 
from typing import Optional, Dict, Any, List

import websockets
import yaml
from ocpp.routing import on, after
from ocpp.v201 import ChargePoint as Cp201, call as call201, call_result as call_result201, datatypes as data201, enums as enums201
from ocpp.v20 import ChargePoint as Cp20, call as call20, call_result as call_result20
from ocpp.v16 import ChargePoint as Cp16, call as call16, call_result as call_result16, datatypes as data16, enums as enum16

from websockets import Subprotocol

import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID


from charging.db import get_event, purge_events, auth_user, get_cps

import netifaces
import argparse
import requests

logging.basicConfig(level=logging.INFO)

CERTIFICATE_PATH = './charging/installedCertificates/server/certificate_server.pem'
CERTIFICATE_KEY_PATH =  './charging/installedCertificates/server/private_key.pem'


# Will be loaded from config.yaml on startup
VERSION = 'v2.0.1'
ACCEPTED_TOKENS = []
ACCEPTED_CHARGES = []
ALLOW_MULTIPLE_SERIAL_NUMBERS = 0
MAX_CONNECTED_CLIENTS = 100_000
HEARTBEAT_INTERVAL = 10
IP = ''
PORT0 = 9000
PORT1 = 9001
PORT2 = 9002
PORT3 = 9003
PORT4 = 9004
PORT5 = 9005
PORT6 = 9006
PORT7 = 9007
URL = ''

# Holds ID and instance of all connected clients
connected_clients = []

# Create the parser
parser = argparse.ArgumentParser(description="Process command-line arguments for server script") 

# Add arguments
parser.add_argument('-config_file', type=str, required=False, help="Path to the configuration file (e.g., ./server_config.yaml)")
parser.add_argument('-iface', type=str, required=False, help="Interface name (e.g., ens33)")
parser.add_argument('-ports', type=int, required=False, nargs='+', help="Ports of the server | SP0_port SP1_port SP2_port SP3_port  (e.g., 9000 9001 9002 9003)")
parser.add_argument('-dns', type=str, required=False, help="DNS Address (e.g., fc00::1)")
parser.add_argument('-url', type=str, required=False, help="URL to give to the DNS server (e.g., ocpp-simulator.com)")
parser.add_argument('-multiple', type=int, required=False, help="Allow multiple serial numbers -> 0 (No) | 1 (Yes) | 2 (No, but allows to steal)")
parser.add_argument('-max_connected', type=int, required=False, help="Maximum number of simultaneous clients connected to the server (e.g., 500)")
parser.add_argument('-heartbeat', type=int, required=False, help="Heartbeat interval (e.g., 10)")

# Parse the arguments
args = parser.parse_args()

if args.config_file != None:
    CONFIG_FILE = args.config_file
else: 
    CONFIG_FILE = 'charging/server_config.yaml'


def _get_current_time() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")



def _get_personal_message(message: str) -> dict:
    return {
        'format': 'ASCII',
        'language': 'en',
        'content': message
    }



# Check if user can be authorized
def _check_authorized(id_token: Dict) -> str:
    # Check if type is correct
    if id_token['type'] not in ('Central', 'eMAID', 'ISO14443', 'ISO15693'):
        return 'Unknown'

    # Check if token is hexadecimal
    try:
        # Check if it can be converted to int from base 16
        int(id_token['id_token'], 16)
    except ValueError:
        return 'Unknown'

    # Check if it respects the specs of the type
    if id_token['type'] == 'Central':
        # Everything is accepted
        pass

    elif id_token['type'] == 'eMAID':
        # Not allowed in this implementation
        return 'Invalid'

    elif id_token['type'] == 'ISO14443':
        # Check if length is either 4 or 7 bytes
        if len(id_token['id_token']) != 8 and len(id_token['id_token']) != 14:
            return 'Invalid'

    elif id_token['type'] == 'ISO15693':
        # Check if length is 8 bytes
        if len(id_token['id_token']) != 16:
            return 'Invalid'

    else:
        return 'Unknown'

    # Check if token is in allowed list
    for i in ACCEPTED_TOKENS:
        if i['type'] == id_token['type'] and i['id_token'] == id_token['id_token']:
            return 'Accepted'

    # If no matching token was found in list
    return 'Invalid'



# Check if new CP is authorized based on vendor, model and serial number
def _check_charger(vendor_name: str, model: str, serial_number: str, password: str = None, certificate: str = None) -> bool:
    for i in ACCEPTED_CHARGES:
        # Check if vendor_name and model match
        if i['vendor_name'] == vendor_name and i['model'] == model:
            # Check if regex matches
            if re.match(i['serial_number_regex'], serial_number):
                return True
    # If no model match, return False
    return False

def load_config() -> bool:
    global ACCEPTED_TOKENS
    global ACCEPTED_CHARGES
    global ALLOW_MULTIPLE_SERIAL_NUMBERS
    global MAX_CONNECTED_CLIENTS
    global HEARTBEAT_INTERVAL
    global IP
    global PORT0
    global PORT1
    global PORT2
    global PORT3
    global PORT4
    global PORT5
    global PORT6
    global PORT7
    global URL
    global DNS

    # Open server config file
    with open(CONFIG_FILE, "r") as file:
        try:
            # Parse YAML content
            content = yaml.safe_load(file)

            if "ip" in content:
                IP = content["ip"]

            if "port0" in content:
                PORT0 = content["port0"]

            if "port1" in content:
                PORT1 = content["port1"]
            
            if "port2" in content:
                PORT2 = content["port2"]

            if "port3" in content:
                PORT3 = content["port3"]

            if "port4" in content:
                PORT4 = content["port4"]

            if "port5" in content:
                PORT5 = content["port5"]
            
            if "port6" in content:
                PORT6 = content["port6"]

            if "port7" in content:
                PORT7 = content["port7"]
            
            if "url" in content:
                URL = content["url"]

            if "dns" in content:
                DNS = content["dns"]

            # Set accepted tokens
            if "accepted_tokens" in content:
                ACCEPTED_TOKENS = content["accepted_tokens"]

            # Set accepted chargers
            if "accepted_chargers" in content:
                ACCEPTED_CHARGES = content["accepted_chargers"]

            # Set security parameters
            if "security" in content:
                if "allow_multiple_serial_numbers" in content["security"]:
                    ALLOW_MULTIPLE_SERIAL_NUMBERS = content["security"]["allow_multiple_serial_numbers"]

                if "max_connected_clients" in content["security"]:
                    MAX_CONNECTED_CLIENTS = content["security"]["max_connected_clients"]

                if "heartbeat_interval" in content["security"]:
                    HEARTBEAT_INTERVAL = content["security"]["heartbeat_interval"]

        except yaml.YAMLError as e:
            print('Failed to parse server_config.yaml')
            return False

        return True

def load_address(interface:str):
    try:
        addrs = netifaces.ifaddresses(interface)
        return addrs[netifaces.AF_INET6][0]['addr']
    except Exception as e:
        print(e)
        print('Not a valid network interface')

def register_with_dns(dns_server_ip, server_ip, port0, port1, port2, port3, port4, port5, port6, port7, url):
    urlR = f"http://[{dns_server_ip}]:5000/register"
    data = {'ip_address': server_ip, 'port0': port0, 'port1': port1, 'port2': port2, 'port3': port3, 'port4': port4, 'port5': port5, 'port6': port6, 'port7': port7, 'url': url}
    response = requests.post(urlR, json=data)
    if response.status_code == 200:
        print(f"Server {server_ip} successfully registered with DNS server.")
    else:
        print(f"Failed to register with DNS server. Status code: {response.status_code}")


def configuration():

    interface = args.iface if args.iface != None else 'ens33'
    addr = load_address(interface = interface)

    with open(CONFIG_FILE, 'r') as file:
        config = yaml.safe_load(file)

    config['ip'] = addr
    if args.ports:
        for i, port in enumerate(args.ports):
            config[f'port{i}'] = port
    if args.multiple != None:
        config['security']['allow_multiple_serial_numbers'] = args.multiple
    if args.max_connected != None:
        config['security']['max_connected_clients'] = args.max_connected
    if args.heartbeat != None:
        config['security']['heartbeat_interval'] = args.heartbeat
    if args.url != None:
        config['url'] = args.url
    if args.dns != None:
        config['dns'] = args.dns

    with open(CONFIG_FILE, 'w') as file:
        yaml.safe_dump(config, file, default_flow_style=False)
        

async def main():

    configuration()

    # Load config file
    if not load_config():
        quit(1)

    # Purge DB
    purge_events()

    
    # Check certificate
    # Load the certificate and private key from files
    try:
        with open(CERTIFICATE_PATH, "rb") as f:
            cert_data = f.read()
            certificate = x509.load_pem_x509_certificate(cert_data, default_backend())

        with open(CERTIFICATE_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    except Exception as e:
        print("Reading certicate/key failed:", e)

    # Check if the certificate has expired
    if certificate.not_valid_before_utc <= datetime.now(certificate.not_valid_before_utc.tzinfo) <= certificate.not_valid_after_utc:
        print("Certificate is currently valid")
    else:
        print("Certificate has expired")
        
    if DNS != None and URL != None:
        register_with_dns(DNS, IP, PORT0, PORT1, PORT2, PORT3, PORT4, PORT5, PORT6, PORT7, URL)

    def make_process_request(passwordType):
        async def process_request(path, request_headers):
            if 'Authorization' in request_headers:
                # Extract the Basic Auth credentials from the headers
                authorization = request_headers.get("Authorization", None).split("Basic ")[1]
                subprotocols = request_headers.get("Sec-WebSocket-Protocol", "")

                if authorization is None:
                    logging.error(f"Authentication failed for {path}. Missing or incorrect Authorization header.")
                    return HTTPStatus.UNAUTHORIZED, [], b"Unauthorized: Missing or invalid Authorization header.\n"

                # Decode the Base64-encoded credentials
                if passwordType == 'Hex':
                    print(base64.b64decode(authorization).decode('utf-8'))
                    decoded_credentials = base64.b64decode(authorization)
                    user_part, password_part = decoded_credentials.split(b':', 1)
                    cp_id = user_part.decode('utf-8')
                    password = password_part.decode('utf-8')
                    print(f'User:   {cp_id}\nPassword:  {password}')
                else:
                    print(base64.b64decode(authorization).decode('utf-8'))
                    decoded_credentials = base64.b64decode(authorization).decode('utf-8')
                    cp_id, password = decoded_credentials.split(':')    
                    print(f'User:   {cp_id}\nPassword:  {password}') 

                # Check the password (simple comparison for this example)
                if not auth_user(cp_id, password):
                    logging.error(f"Authentication failed for {path}. Incorrect password.")
                    return HTTPStatus.UNAUTHORIZED, [], b"Unauthorized: Incorrect password.\n"
                
                logging.info(f"Authentication successful for {cp_id}.")
            else:
                logging.error(f"Authentication failed for {path}. No password given.")
                return HTTPStatus.UNAUTHORIZED, [], b"Unauthorized: No password password given.\n"
        return process_request

    context2 = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context2.load_cert_chain(CERTIFICATE_PATH, CERTIFICATE_KEY_PATH)
    context2.minimum_version = ssl.TLSVersion.TLSv1_2
    context2.load_verify_locations('./charging/installedCertificates/server/root/emuocpp_ttp_cert.pem')
    context2.check_hostname = False 
    context2.verify_mode = ssl.CERT_NONE 

    context3 = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context3.load_cert_chain(CERTIFICATE_PATH, CERTIFICATE_KEY_PATH)
    context3.minimum_version = ssl.TLSVersion.TLSv1_2
    context3.load_verify_locations(cafile='./charging/installedCertificates/server/root/emuocpp_ttp_cert.pem')
    context3.check_hostname = True 
    context3.verify_mode = ssl.CERT_REQUIRED

    # Start websocket with callback function
    server_zero = await websockets.serve(
        on_connect, IP, PORT0, subprotocols=[Subprotocol("ocpp1.6")]
    )

    # Start websocket with callback function
    server_one = await websockets.serve(
        on_connect, IP, PORT1, subprotocols=[Subprotocol("ocpp1.6")], process_request=make_process_request(passwordType = 'Hex')
    )
    
    # Start websocket with callback function
    server_two = await websockets.serve(
        on_connect, IP, PORT2, subprotocols=[Subprotocol("ocpp1.6")], process_request=make_process_request(passwordType = 'Hex'), ssl = context2
    )

    # Start websocket with callback function
    server_three = await websockets.serve(
        on_connect, IP, PORT3, subprotocols=[Subprotocol("ocpp1.6")], ssl = context3
    )

    # Start websocket with callback function
    server_four = await websockets.serve(
        on_connect, IP, PORT4, subprotocols=[Subprotocol("ocpp2.0.1"), Subprotocol("ocpp2.0")]
    )

    # Start websocket with callback function
    server_five = await websockets.serve(
        on_connect, IP, PORT5, subprotocols=[Subprotocol("ocpp2.0.1"), Subprotocol("ocpp2.0")], process_request=make_process_request(passwordType = 'nonHex')
    )
    
    # Start websocket with callback function
    server_six = await websockets.serve(
        on_connect, IP, PORT6, subprotocols=[Subprotocol("ocpp2.0.1"), Subprotocol("ocpp2.0")], process_request=make_process_request(passwordType = 'nonHex'), ssl = context2
    )

    # Start websocket with callback function
    server_seven = await websockets.serve(
        on_connect, IP, PORT7, subprotocols=[Subprotocol("ocpp2.0.1"), Subprotocol("ocpp2.0")], ssl = context3
    )

    # Start websocket with callback function
    server_eight = await websockets.serve(
        on_operator, IP, 9008
    )

    # Wait for server to be closed down
    await server_zero.wait_closed()
    await server_one.wait_closed()
    await server_two.wait_closed()
    await server_three.wait_closed()
    await server_four.wait_closed()
    await server_five.wait_closed()
    await server_six.wait_closed()
    await server_seven.wait_closed()
    await server_eight.wait_closed()

        

# Define a base class with common functionality
class ChargePointServerBase:

    is_booted: bool = False
    is_authorized: bool = False
    status: str = 'Available'
    charging_state: str = 'Idle'

    csr_data = None

    serial_number = ''

    SECURITY_PROFILE = 0

    last_reservation_id = 0
    transaction_counter = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
    
    # Periodically check for new reservation requests
    async def _check_reservations(self, interval: int = 1):
        while True:
            # Get first reserve_now event
            data = get_event('reserve_now', target=self.id, first_acceptable_id=self.last_reservation_id + 1)

            # If event is there
            if data is not None:
                logging.info(f"Processing event reserve_now with data {data}")

                event_id, token = data

                # Send ReserveNow payload
                if VERSION == "v2.0.1":
                    await self.send_reserve_now(
                        id=event_id,
                        expiry_date_time=(datetime.utcnow() + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S") + "Z",
                        id_token=token
                    )
                elif VERSION == "v2.0":
                    await self.send_reserve_now(
                        id=event_id,
                        expiry_date_time=(datetime.utcnow() + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S") + "Z",
                        id_token=token,
                        evse_id={'id': 1}
                    )
                elif VERSION == 'v1.6':
                    await self.send_reserve_now(
                    id=event_id,
                    expiry_date_time=(datetime.utcnow() + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S") + "Z",
                    id_token=token["id_token"]
                )

                # Set new last reservation id to current id
                self.last_reservation_id = event_id

            # Wait for set time
            await asyncio.sleep(interval)

    async def _check_events(self, interval: int =1):
        while True:
            if self.csr_data != None:
                # Load the emuocpp-ttp private key and certificate
                with open('emuocpp_ttp_key.pem', 'rb') as f:
                    ca_private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

                with open('emuocpp_ttp_cert.pem', 'rb') as f:
                    ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

                cert = (
                    x509.CertificateBuilder()
                    .subject_name(self.csr_data.subject)
                    .issuer_name(ca_cert.subject)  # Use emuocpp-ttp as the issuer
                    .public_key(self.csr_data.public_key())  # The public key of the client/server
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(datetime.now(timezone.utc))
                    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365 * 2))  # Valid for 2 years
                    .add_extension(
                        x509.BasicConstraints(ca=False, path_length=None), critical=True
                    )
                    .sign(ca_private_key, hashes.SHA256(), default_backend())  # Sign using emuocpp-ttp's private key
                )
                certificate_pem = cert.public_bytes(encoding=serialization.Encoding.PEM).decode()
                await self.send_certificate_signed(certificate_pem)
                self.csr_data = None
            # Wait for set time
            await asyncio.sleep(interval)
    
    async def send_install_certificate(
            self,
            type: str,
            certificate: str,
            version: str
    ):
        print(f'Installing {type} certificate to {self.serial_number}')
        if version == 'v2.0.1':
            request = call201.InstallCertificatePayload(type, certificate)
        elif version == 'v2.0':
            request = call20.InstallCertificatePayload(type, certificate)
        else:
            request = call16.InstallCertificatePayload(type, certificate)
        
        response = await self.call(request)

        if response.status != "Accepted":
            logging.error("Certificate installation failed")
            return False
        else:
            print(f'{type} certificate installed correctly into {self.serial_number}')
            return True

        
    async def send_get_variable(
            self,
            version: str,
            data201: data201.GetVariableDataType = None,
            data16: List = None            
    ):
        print(f'Obtaining {data201 if data201 else data16} from {self.serial_number}')
        if version == 'v2.0.1':
            request = call201.GetVariablesPayload(data201)
        elif version == 'v2.0':
            request = call20.GetVariablesPayload(data201)
        else:
            request = call16.GetConfigurationPayload(data16)
        
        response = await self.call(request)
        final = "\n"
        if version != 'v1.6':
            for result in response.get_variable_result:
                final += f'{result["variable"]["name"]}: {result["attribute_value"] if result["attribute_status"] == "Accepted" else result["attribute_status"]}\n'
            return final
        else:
            for result in response.configuration_key:
                final += f'{result["key"]}: {result["value"]}\n'
            return final

    async def send_set_variable(
            self,
            version: str,
            data: list           
    ):
        print(f'Setting {data} into {self.serial_number}...')
        request = None
        request16 = None
        if version == 'v2.0.1':
            request = call201.SetVariablesPayload(set_variable_data=data)
        elif version == 'v2.0':
            request = call20.SetVariablesPayload(set_variable_data=data)
        elif version == 'v1.6':
            request16 = call16.ChangeConfigurationPayload(key=data[0][0], value=str(data[0][1]))
        
        if request != None:
            response = await self.call(request)
            response16 = None
        else:
            response16 = await self.call(request16)
            response = None

        final = "\n"
        if response != None:
            for result in response.set_variable_result:
                final += f'{result["variable"]["name"]}: {result["attribute_status"]}\n'
                if result["attribute_status"] == 'RebootRequired':
                    reb = await self.send_reboot(version)
                    if reb:
                        final += 'CP rebooting...\n'
        else:
            final += f'{data[0][0]}: {response16.status}\n'
        return final
    
    async def send_reboot(
            self,
            version: str
    ):
        if version == 'v2.0.1':
            request = call201.ResetPayload(type=enums201.ResetType.on_idle.value)
        elif version == 'v2.0':
            request = call20.ResetPayload(type=enums201.ResetType.on_idle.value)

        response = await self.call(request)

        if response.status != "Accepted":
            logging.error("Reboot failed")
            return False
        else:
            print(f'{self.serial_number} rebooting...')
            return True
        
    async def send_trigger_message(
            self,
            version: str,
            reason: str
    ):
        try:
            if version == 'v2.0.1':
                request = call201.TriggerMessagePayload(requested_message=reason)
            elif version == 'v2.0':
                request = call20.TriggerMessagePayload(requested_message=reason)
            elif version == 'v1.6':
                request = call16.ExtendedTriggerMessagePayload(requested_message=reason)
        except:
            print('Invalid trigger reason.')

        response = await self.call(request)

        if response.status != "Accepted":
            logging.error("Trigger message failed")
            return False
        else:
            print(f'{self.serial_number} accpeted to trigger {reason}')
            return True


    async def send_set_network(
            self,
            version: str,
            slot: int,
            data: data201.NetworkConnectionProfileType            
    ):
        print(f'Setting {data} into {self.serial_number}...')

        if version == 'v2.0.1':
            request = call201.SetNetworkProfilePayload(configuration_slot= slot, connection_data=data)
        elif version == 'v2.0':
            request = call20.SetNetworkProfilePayload(configuration_slot= slot, connection_data=data)

        response = await self.call(request)

        if response.status != "Accepted":
            logging.error("NetworProfile setting failed")
            return False
        else:
            print(f'Setting {data} NetworkProfile into {self.serial_number} failed')
            return True
   
    @on("BootNotification")
    async def on_boot_notification(
        self,
        charge_point_model: str = None,
        charge_point_vendor: str = None,
        charge_box_serial_number: str = None,
        charge_point_serial_number: str = None,
        firmware_version: str = None,
        meter_serial_number: str = None,
        charging_station: Dict = None,
        reason: str = None,
        custom_data: Optional[Dict[str, Any]] = None
    ):

        port = self._connection.local_address[1] 
        if port == PORT0:
            self.SECURITY_PROFILE = 0
        elif port == PORT1:
            self.SECURITY_PROFILE = 1
        elif port == PORT2:
            self.SECURITY_PROFILE = 2
        elif port == PORT3:
            self.SECURITY_PROFILE = 3
        elif port == PORT4:
            self.SECURITY_PROFILE = 0
        elif port == PORT5:
            self.SECURITY_PROFILE = 1
        elif port == PORT6:
            self.SECURITY_PROFILE = 2
        elif port == PORT7:
            self.SECURITY_PROFILE = 3

        if VERSION == 'v1.6':
            logging.info(f"Got boot notification from {charge_point_serial_number} and security profile {self.SECURITY_PROFILE}")
            self.chargePoint = {'model': charge_point_model, 'vendor_name': charge_point_vendor, 'serial_number': charge_point_serial_number}
        else:
            logging.info(f"Got boot notification from {charging_station} for reason {reason} and security profile {self.SECURITY_PROFILE}")

        # Check if new CP has valid vendor, model and serial number
        if VERSION == 'v1.6':
            self.is_booted = _check_charger(**self.chargePoint)
        else:
            self.is_booted = _check_charger(**charging_station)

        if self.is_booted:
            self.serial_number = charge_point_serial_number if VERSION == 'v1.6' else charging_station['serial_number']

        if VERSION == 'v2.0.1':
            return call_result201.BootNotificationPayload(
                current_time=_get_current_time(),
                interval=HEARTBEAT_INTERVAL,
                status=('Accepted' if self.is_booted else 'Rejected')
            )

        elif VERSION == 'v2.0':
            return call_result20.BootNotificationPayload(
                current_time=_get_current_time(),
                interval=HEARTBEAT_INTERVAL,
                status=('Accepted' if self.is_booted else 'Rejected')
            )
        
        elif VERSION == 'v1.6':
            return call_result16.BootNotificationPayload(
                current_time=_get_current_time(),
                interval=HEARTBEAT_INTERVAL,
                status=('Accepted' if self.is_booted else 'Rejected')
            )
            
    @after("BootNotification")
    async def after_boot_notification(self, *args, **kwargs):
        # If the CP was not booted (which means rejected)
        if not self.is_booted:
            # Force close websocket
            await self._connection.close()

    @on("Heartbeat")
    def on_heartbeat(
        self,
        custom_data: Optional[Dict[str, Any]] = None
    ):
        if VERSION == 'v2.0.1':
            return call_result201.HeartbeatPayload(
                current_time=_get_current_time()
            )
        elif VERSION == 'v2.0':
            return call_result20.HeartbeatPayload(
                current_time=_get_current_time()
            )
        elif VERSION == 'v1.6':
            return call_result16.HeartbeatPayload(
                current_time=_get_current_time()
            )
        
    @on("Authorize")
    def on_authorize(
        self,
        id_token: Dict,
        certificate: Optional[str] = None,
        iso15118_certificate_hash_data: Optional[List] = None,
        custom_data: Optional[Dict[str, Any]] = None
    ):
        logging.info(f"Got authorization request from {id_token}")

        if VERSION == 'v2.0.1':
            return call_result201.AuthorizePayload(id_token_info={"status": _check_authorized(id_token)})
        elif VERSION == 'v2.0':
            return call_result20.AuthorizePayload(id_token_info={"status": _check_authorized(id_token)})
        elif VERSION == 'v1.6':
            return call_result16.AuthorizePayload(id_tag_info=data16.IdTagInfo(status=_check_authorized(id_token)))

        
    @on("StatusNotification")
    def on_status_notification(
        self,
        timestamp: str,
        connector_status: str = None,
        evse_id: int = None,
        connector_id: int = None,
        error_code: int = None,
        status: str = None,
        custom_data: Optional[Dict[str, Any]] = None
    ):
        self.status = connector_status
        if status:
            logging.info(f'Connector: {connector_id} is {status}')
        if error_code != 'NoError':
            logging.error(f'Problem with connector: {connector_id} with error: {error_code}')

        if VERSION == 'v2.0.1':
            return call_result201.StatusNotificationPayload()
        elif VERSION == 'v2.0':
            return call_result20.StatusNotificationPayload()
        elif VERSION == 'v1.6':
            return call_result16.StatusNotificationPayload()


    @on("StartTransactionPayload")
    def on_start_transaction(self, id_tag: str, meter_start: int, timestamp: str):
        logging.info(f"Starting transaction for ID tag {id_tag}")

        if not self.is_authorized:
            logging.error("User is not authorized to start transaction")
            return

        transaction_counter += 1
        current_time = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        transaction_id = f"{current_time}{self.transaction_counter:04}"
        transaction_id = int(transaction_id)

        self.current_transaction_id = transaction_id

        return call_result16.StartTransactionPayload(
            transaction_id=transaction_id,
            id_tag_info=data16.IdTagInfo(status="Accepted")
        )

    @on("StopTransactionPayload")
    def on_stop_transaction(self, transaction_id: int, meter_stop: int, timestamp: str):
        logging.info(f"Stopping transaction with ID {transaction_id}")
        return call_result16.StopTransactionPayload(
           id_tag_info=data16.IdTagInfo(status="Accepted")
        )


    @on("TransactionEvent")
    def on_transaction_event(
        self,
        event_type: str,
        timestamp: str,
        trigger_reason: str,
        seq_no: int,
        transaction_info: Dict,
        meter_value: Optional[List] = None,
        offline: Optional[bool] = None,
        number_of_phases_used: Optional[int] = None,
        cable_max_current: Optional[int] = None,
        reservation_id: Optional[int] = None,
        evse: Optional[Dict] = None,
        id_token: Optional[Dict] = None,
        custom_data: Optional[Dict[str, Any]] = None
    ):
        logging.info(f"Got transaction event {event_type} because of {trigger_reason} with id {transaction_info['transaction_id']}")

        # When receiving an "Authorized" event
        if trigger_reason == "Authorized":

            # Check if authorized
            auth_result = _check_authorized(id_token)
            if auth_result != "Accepted":
                logging.error(f"User is not authorized for reason {auth_result}")
                
                if VERSION == 'v2.0.1':
                    return call_result201.AuthorizePayload(id_token_info={"status": auth_result})
                elif VERSION == 'v2.0':
                    return call_result20.AuthorizePayload(id_token_info={"status": auth_result})
                
                
            logging.info(f"User is authorized")

            # Set as authorized
            self.is_authorized = True
            # Respond
            if VERSION == 'v2.0.1':
                return call_result201.TransactionEventPayload(
                    id_token_info={"status": 'Accepted'},
                    updated_personal_message=_get_personal_message('Charging is Authorized')
                )
            elif VERSION == 'v2.0':
                return call_result20.TransactionEventPayload(
                    id_token_info={"status": 'Accepted'},
                    updated_personal_message=_get_personal_message('Charging is Authorized')
                )

        # When receiving a "CablePluggedIn" event
        elif trigger_reason == "CablePluggedIn":

            logging.info(f"Cable plugged in")

            # Respond
            if VERSION == 'v2.0.1':
                return call_result201.TransactionEventPayload(
                    updated_personal_message=_get_personal_message('Cable is plugged in')
                )
            elif VERSION == 'v2.0':
                return call_result20.TransactionEventPayload(
                    updated_personal_message=_get_personal_message('Cable is plugged in')
                )

        # When receiving a "ChargingStateChanged" event
        elif trigger_reason == "ChargingStateChanged":

            logging.info(f"Charging state changed to {transaction_info['charging_state']}")

            # Set correct charging state
            self.charging_state = transaction_info['charging_state']

            # Get correct charging message
            if self.charging_state == "Charging":
                message = "Charging started"
            elif self.charging_state in ("SuspendedEV", "SuspendedEVSE"):
                message = "Charging suspended"
            elif self.charging_state == "Idle":
                message = "Charging stopped"
            else:
                message = "Unknown"

            # Respond
            if VERSION == 'v2.0.1':
                return call_result201.TransactionEventPayload(
                    updated_personal_message=_get_personal_message(message)
                )
            elif VERSION == 'v2.0':
                return call_result20.TransactionEventPayload(
                    updated_personal_message=_get_personal_message(message)
                )

        # When receiving any other event
        if VERSION == 'v2.0.1':
            return call_result201.TransactionEventPayload(
                updated_personal_message=_get_personal_message("Not implemented")
            )
        elif VERSION == 'v2.0':
            return call_result201.TransactionEventPayload(
                updated_personal_message=_get_personal_message("Not implemented")
            )

    @on('SignCertificate')
    async def on_sign_certificate(
            self,
            csr: str
    ):
        self.csr_data = x509.load_pem_x509_csr(csr.encode(), default_backend())
        
        if VERSION == 'v2.0.1':
            return call_result201.SignCertificatePayload(status='Accepted')
        elif VERSION == 'v2.0':
            return call_result20.SignCertificatePayload(status='Accepted')
        elif VERSION == 'v1.6':
            return call_result16.SignCertificatePayload(status='Accepted')

    async def send_certificate_signed(
            self,
            certificate: str
    ):
        if VERSION == 'v2.0.1':
            request = call201.CertificateSignedPayload(certificate_chain=certificate)
        elif VERSION == 'v2.0':
            request = call20.CertificateSignedPayload(cert=[certificate])
        elif VERSION == 'v1.6':
            request = call16.CertificateSignedPayload(certificate_chain=certificate)

        response = await self.call(request)

        print(request)


    async def send_reserve_now(
        self,
        id: int,
        expiry_date_time: str,
        id_token: Dict,
        connector_type: Optional[str] = None,
        evse_id: Optional[int] = None,
        group_id_token: Optional[Dict] = None,
        custom_data: Optional[Dict[str, Any]] = None
    ):
        if VERSION == 'v2.0.1':
            await self.call(call201.ReserveNowPayload(
                id=id,
                expiry_date_time=expiry_date_time,
                id_token=id_token,
                connector_type=connector_type,
                evse_id=evse_id,
                group_id_token=group_id_token,
                custom_data=custom_data
            ))
        elif VERSION == 'v2.0':
             await self.call(call20.ReserveNowPayload(
                id_token=id_token,
                reservation = {"id": id, "expiry_date_time": expiry_date_time, "connector_code": connector_type, "evse": evse_id},
                group_id_token=group_id_token
        ))
        elif VERSION == 'v1.6':
            await self.call(call16.ReserveNowPayload( 
                connector_id=1,
                expiry_date=expiry_date_time,
                id_tag=id_token,
                reservation_id=id
            ))

# Factory function to create the correct subclass
def ChargePointServerFactory(version):
    if version == "v2.0.1":
        class ChargePointServer(Cp201, ChargePointServerBase):
            pass
        return ChargePointServer

    elif version == "v2.0":
        class ChargePointServer(Cp20, ChargePointServerBase):
            pass
        return ChargePointServer
    
    elif version == "v1.6":
        class ChargePointServer(Cp16, ChargePointServerBase):
            pass
        return ChargePointServer

    else:
        raise ValueError("Unsupported OCPP version")
    
def load_certificate(cert_path):
    # Read the certificate from the file
    with open(cert_path, 'r') as cert_file:
        cert_data = cert_file.read()
    # Ensure the certificate length is within the allowed bounds 
    if len(cert_data) > 5500:
        raise ValueError("Certificate exceeds maximum allowed length (5500 characters).")
    return cert_data

async def on_operator(websocket, path):
    async for message in websocket:
        if message == "list":
            # Send the list of connected clients back to the operator
            await websocket.send(f"Connected Clients: {connected_clients}")
        elif message.startswith("ping"):
            pass
        elif message.startswith("install"):
            order, serial = message.split(' ')
            var = False
            for cp_id, cp_ws, version in connected_clients:
                if cp_id == serial:
                    res = await cp_ws.send_install_certificate('CSMSRootCertificate' if version != 'v1.6' else 'CentralSystemRootCertificate', load_certificate('./charging/installedCertificates/server/root/emuocpp_ttp_cert.pem'), version)
                    if res:
                        await websocket.send(f"Certificate installed into: {serial}")
                    else:
                        await websocket.send(f"Certificate installation failed")
                    var = True
                if var:
                    break
            if not var:
                await websocket.send(f"Charging station with ID :{serial} not found")
        elif message.startswith("get"):
            messageParts = message.split(' ')
            serial = messageParts[1]
            variables = messageParts[2:]
            var = False
            for cp_id, cp_ws, version in connected_clients:
                if cp_id == serial:
                    vars = []
                    for variable in variables:
                        if variable in ('HeartbeatInterval', 'MessageTimeout', 'NetworkConfigurationPriority', 'NetworkProfileConnectionAttempts', 'OfflineThreshold', 'ActiveNetworkProfile'):
                            component = {"name": "OCPPCommCtrlr"}
                        elif variable in ('AdditionalRootCertificateCheck', 'BasicAuthPassword', 'CertSigningRepeatTimes', 'CertSigningWaitMinimum', 'Identity', 'OrganizationName', 'SecurityProfile'):
                            component = {"name": "SecurityCtrlr"}
                        variable201 =  {"name": variable}
                        if version != 'v1.6':
                            data = data201.GetVariableDataType(component=component, variable=variable201)
                            vars.append(data)
                            
                        else:
                            vars.append(variable)
                    if version != 'v1.6':
                        response = await cp_ws.send_get_variable(version= version, data201= vars)
                    else:
                        response = await cp_ws.send_get_variable(version= version, data16= vars)
                    await websocket.send(f"Data: {response}")
                    var = True
                if var:
                    break
            if not var:
                await websocket.send(f"Charging station with ID :{serial} not found")
            
        elif message.startswith("setProfile"):
            messageParts = message.split(' ')
            serial = messageParts[1]
            variables = messageParts[2:]
            var = False
            for cp_id, cp_ws, version in connected_clients:
                if cp_id == serial:
                    res = await cp_ws.send_set_network(version= version, slot=int(variables[0]), data=data201.NetworkConnectionProfileType(ocpp_version='OCPP16' if version == 'v1.6' else 'OCPP20', ocpp_transport= "JSON", ocpp_csms_url=IP, message_timeout=30, security_profile=int(variables[1]), ocpp_interface=enums201.OCPPInterfaceType.wireless0.value))
                    if res:
                        await websocket.send(f"NetworkProfile set into: {serial}")
                    else:
                        await websocket.send(f"NetworkProfile setting failed")
                    var = True
                if var:
                    break
            if not var:
                await websocket.send(f"Charging station with ID :{serial} not found")
        elif message.startswith("setVariable"):
            messageParts = message.split(' ')
            serial = messageParts[1]
            variables = messageParts[2:]
            var = False
            dataList = []
            for cp_id, cp_ws, version in connected_clients:
                if cp_id == serial:
                    for element in variables:
                        variable = ast.literal_eval(element)[0]
                        data = ast.literal_eval(element)[1]
                        if variable in ('HeartbeatInterval', 'MessageTimeout', 'NetworkConfigurationPriority', 'NetworkProfileConnectionAttempts', 'OfflineThreshold', 'ActiveNetworkProfile'):
                            component = {"name": "OCPPCommCtrlr"}
                        elif variable in ('AdditionalRootCertificateCheck', 'BasicAuthPassword', 'CertSigningRepeatTimes', 'CertSigningWaitMinimum', 'Identity', 'OrganizationName', 'SecurityProfile'):
                            component = {"name": "SecurityCtrlr"}
                        if version != 'v1.6':
                            dataList.append(data201.SetVariableDataType(component=component, variable={"name": variable}, attribute_value=str(data)))
                        else:
                            dataList.append([variable, data])
                    res = await cp_ws.send_set_variable(version= version, data=dataList)
                    if res:
                        await websocket.send(f"{res}")
                    else:
                        await websocket.send(f"Variables setting failed")
                    var = True
                if var:
                    break
            if not var:
                await websocket.send(f"Charging station with ID :{serial} not found")
        elif message.startswith("trigger"):
            messageParts = message.split(' ')
            serial = messageParts[1]
            reason = messageParts[2]
            var = False
            for cp_id, cp_ws, version in connected_clients:
                if cp_id == serial:
                    res = await cp_ws.send_trigger_message(version= version, reason = reason)
                    if res:
                        await websocket.send(f"Trigger message accepted")
                    else:
                        await websocket.send(f"Trigger message failed")
                    var = True
                if var:
                    break
            if not var:
                await websocket.send(f"Charging station with ID :{serial} not found")
        else:
            await websocket.send(f"Unknown order: {message}")

async def on_connect(websocket, path):
    global VERSION
    # Extract the SSL object to access certificate details
    ssl_object = websocket.transport.get_extra_info('ssl_object')
    if ssl_object:
        # Get the client certificate in DER format
        client_cert_der = ssl_object.getpeercert()
        if client_cert_der is None:
            print("No client certificate provided!")
        else:
            def get_data_from_cert(cert_pem):
                res = {}
                for element in client_cert_der['subject']:
                    for name, data in element:
                        if name == 'commonName':
                            res['commonName'] = data
                        elif name == 'organizationName':
                            res['organizationName'] = data
                return res
            # Extract the Common Name (CN) from the client certificate
            cert_data = get_data_from_cert(client_cert_der)
            
            # Reject the connection if the CN is not valid
            if cert_data['commonName'] not in get_cps() or cert_data['commonName'] != path.strip("/") or cert_data['organizationName'] != 'EmuOCPP':
                print(f"Unauthorized client, closing connection.")
                await websocket.close()
                return

    try:
        requested_protocols = websocket.request_headers["Sec-WebSocket-Protocol"]
        if requested_protocols == "ocpp2.0.1":
            VERSION = 'v2.0.1'
        elif requested_protocols == "ocpp2.0":
            VERSION = 'v2.0'
        elif requested_protocols == "ocpp1.6":
            VERSION = 'v1.6' 
    
    except KeyError:
        logging.error("Client hasn't requested any protocol. Closing Connection")
        return await websocket.close() 

    # Check if protocol matches with the one on the server
    if websocket.subprotocol:
        logging.info("Protocols Matched: %s", websocket.subprotocol)
    else:
        logging.error(f"Protocols Mismatched: client is using {websocket.subprotocol}. Closing connection")
        return await websocket.close()

    # Get id from path
    charge_point_id = path.strip("/")
    
    # Initialize CP

    ChargePointServer = ChargePointServerFactory(VERSION)
    cp = ChargePointServer(charge_point_id, websocket)
    added = False
    # If only one CP per id is allowed, check it doesn't exist
    for cp_id, cp_ws, version in connected_clients:
        if cp_id == charge_point_id:
            if ALLOW_MULTIPLE_SERIAL_NUMBERS == 0:
                logging.error(f"Client tried to connect with ID {cp_id}, but another client already exists")
                return await websocket.close()
            elif ALLOW_MULTIPLE_SERIAL_NUMBERS == 1:
                logging.info(f'Client duplicated detected with ID {cp_id}')
                connected_clients.append((charge_point_id, cp, VERSION))
                added = True
                break
            elif ALLOW_MULTIPLE_SERIAL_NUMBERS == 2:
                logging.info(f'Client duplicated detected with ID {cp_id}\nClosing previous connection...')
                connected_clients.remove((cp_id, cp_ws, version))
                await cp_ws._connection.close()
                connected_clients.append((charge_point_id, cp, VERSION))
                added = True
    if not added:
        connected_clients.append((charge_point_id, cp, VERSION))


    if len(connected_clients) >= MAX_CONNECTED_CLIENTS:
        logging.error("Server is overloaded, quitting")
        quit(2)

    # Start and await for disconnection
    try:
        await asyncio.gather(cp.start(), cp._check_reservations(), cp._check_events())
    except websockets.exceptions.ConnectionClosed:
        logging.info(f"Client {charge_point_id} disconnected")
        if (charge_point_id, cp, VERSION) in connected_clients:
            # Remove from list of connected clients
            connected_clients.remove((charge_point_id, cp, VERSION))
    except Exception as e:
        print(e)


if __name__ == "__main__":
    asyncio.run(main())