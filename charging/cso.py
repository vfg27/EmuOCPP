import argparse
import asyncio
import websockets
import readline  

# Create the parser
parser = argparse.ArgumentParser(description="Process command-line arguments for CSO script")

# Add arguments
parser.add_argument('-server', type=str, required=False, help="Server IPv6 address (e.g., ::1)")

# Parse the arguments
args = parser.parse_args()

# Set the server IP address
if args.server:
    ip = args.server
else:
    ip = 'fe80::e3a6:46e4:bff9:fb8e%ens160'

cmd_list = ['list', 'exit', 'help', 'install', 'get', 'setProfile', 'setVariable', 'trigger', 'ping']

async def process_command(command, websocket):
    # Handle exit command
    if command == 'exit':
        await websocket.close()
        return False

    # Send the command to the server and print the response
    await websocket.send(command)
    if command != 'ping':
        response = await websocket.recv()
        print(f"Server response: {response}")
    else:
        print('\nSending ping...\n')

    return True

async def send_order():
    try:
        uri = f"ws://[{ip}]:9008"  # Operator server address
        async with websockets.connect(uri) as websocket:
            print("Connected to the server.")
                       
            while True:
                # Prompt for command
                print("Insert command: ", end='', flush=True)
                try:
                    command = await asyncio.wait_for(asyncio.to_thread(input), timeout=30)
                except TimeoutError:
                    command = 'ping'
                
                if command == 'cmd1':
                    command = 'setVariable E2507-8420-1274 ("NetworkConfigurationPriority",[1,2,0])'
                elif command == 'cmd2':
                    command = 'setVariable E2507-8420-1274 ("NetworkConfigurationPriority",[2,1,0])'
                elif command == 'cmd3':
                    command = 'trigger E2507-8420-1274 SignChargingStationCertificate'
                elif command == 'cmd4':
                    command = 'setVariable E2507-8420-1275 ("SecurityProfile",2)'
                elif command == 'cmd5':
                    command = 'setVariable E2507-8420-1275 ("SecurityProfile",3)'
                elif command == 'cmd6':
                    command = 'trigger E2507-8420-1275 SignChargePointCertificate'

                order = command.split(' ')

                if order[0] == 'help':
                    print('\nAvailable commands:\n')
                    print('"list" --- Print the connected CS in the server\n')
                    print('"exit" --- Close the connection\n')
                    print('"install <CP_ID>" --- Install the root certificate in the CP with the CP_ID passed as parameter\n')
                    print('"get <CP_ID> <variable> ..." --- Get the demanded variable from the CP\n')
                    print('"trigger <CP_ID> <reason> ..." --- Send trigger message to the desired CP\n')
                    print('"setProfile <CP_ID> <slot> <security_profile>" --- Set a NetworkProfile with the desired security profile into the CP\n')
                    print('"setVariable <CP_ID> ("<variable>",<data>) ..." --- Set a variables with the desired value into the CP (if data is a string put it in "")\n')
                elif order[0] in cmd_list:
                    # Process command
                    if not await process_command(command, websocket):
                        break
                else:
                    print('Command not found. Type "help" to obtain the command list.')
    except websockets.exceptions.ConnectionClosedError as e:
        print(f"WebSocket closed with error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        print("Connection closed, exiting program.")
        

# Run the client
asyncio.run(send_order())
