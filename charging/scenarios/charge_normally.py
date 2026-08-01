import sys
sys.path.append('.')

import asyncio
import logging
from uuid import uuid4

import yaml
CONFIG_FILE = 'charging/server_config.yaml'
# Open server config file
with open(CONFIG_FILE, "r") as file: 
    try:
        # Parse YAML content
        content = yaml.safe_load(file)

        if "version" in content:
            VERSION = content["version"]
    except yaml.YAMLError as e:
        print('Failed to parse server_config.yaml')

from charging.client import launch_client, ChargePointClientBase, wait_for_button_press, load_config, CONFIGURATION

logging.basicConfig(level=logging.ERROR)


# ID of the RFID token used to authenticate
RFID_TOKEN = '1122334455667788'
TOKEN_TYPE = 'ISO15693'


# Emulates a normal charging process:
#   1. Authentication
#   2. Plug cable in
#   3. Start charging
async def charge_normally(cp: ChargePointClientBase):
    cp.print_message('Connected to server')

    # Generate unique ID for future transaction
    transaction_id = str(uuid4())

    # === AUTHORIZATION ===

    await wait_for_button_press('AUTHORIZATION')

    # Send authorization request
    response = await cp.send_authorize({'type': TOKEN_TYPE, 'id_token': RFID_TOKEN })

    # Check if authorization was accepted
    if response.id_token_info['status'] != "Accepted":
        logging.error("Authorization failed")
        return
    else:
        cp.print_message("Charging point authorization successful!")

    # Send authorized transaction event
    response = await cp.send_transaction_event_authorized(
        'Started',
        transaction_id,
        1,
        {'type': TOKEN_TYPE, 'id_token': RFID_TOKEN}
    )

    # Check if authorization was accepted
    if response.id_token_info['status'] != "Accepted":
        logging.error("Authorization failed")
        return
    else:
        cp.print_message(f"Central authorization successful! Server message: '{response.updated_personal_message['content']}'")

    # === PLUG IN CABLE ===

    await wait_for_button_press('PLUG IN CABLE')

    # Send occupied notification (no meaningful response)
    await cp.send_status_notification('Occupied')
    cp.print_message("Sent status notification for occupied cable")

    # Send cable plugged in transaction event
    response = await cp.send_transaction_event_cable_plugged_in('Updated', transaction_id, 2)
    cp.print_message(f"Cable plug in successful! Server message: '{response.updated_personal_message['content']}'")

    # === START CHARGING ===

    await wait_for_button_press('START CHARGING')

    # Send cable plugged in transaction event
    response = await cp.send_transaction_event_charging_state_changed('Updated', transaction_id, 3, 'Charging')
    cp.print_message(f"Started charging! Server message: '{response.updated_personal_message['content']}'")


if __name__ == "__main__":

    config = {
        'vendor_name': 'EmuOCPPCharge',
        'model': 'E2507',
        'index':1
        }
    
    # Load config file
    if not load_config():
        quit(1)
    
    asyncio.run(launch_client(**config, async_runnable=charge_normally))
