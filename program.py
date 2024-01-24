from typing import TypedDict
from core import pack

class PeerData(TypedDict):
    """
        'description' is a name of connection
        'client_ip' is an ip from config file
        'client_priv_key' is a private key from config
        'client_pub_key' is a public key from config
        'address' is an address from config, e.g. 10.66.66.2/32,
        'preshared_key' is a PresharedKey from config file
        'endpoint' is an address with port e.g. 200.14.33.82:54040
        'hostName' just an ip
        'port' just a port
    """
    description: str
    client_ip: str
    client_priv_key: str
    client_pub_key: str
    preshared_key: str
    hostName: str
    port: str


def start() -> None:
    peer_data: PeerData = {}
    for key, annotation in PeerData.__annotations__.items():
        user_input = input(f"Enter value for {key}: ")
        peer_data[key] = user_input

    json = generate_json(peer_data)

    print(pack(json))


def generate_json(peer_data: PeerData) -> str:
    last_config = f'''
    {{
        "H1": "0",
        "H2": "0",
        "H3": "0",
        "H4": "0",
        "Jc": "2",
        "Jmax": "1000",
        "Jmin": "1",
        "S1": "0",
        "S2": "0",
        "client_ip": {peer_data['client_ip']},
        "client_priv_key": "{peer_data['client_priv_key']}",
        "client_pub_key": "{peer_data['client_pub_key']}",
        "config": "[Interface]\\nAddress = {peer_data['client_ip']}/32\\nDNS = $PRIMARY_DNS, $SECONDARY_DNS\\nPrivateKey = {peer_data['client_priv_key']}\\nJc = 2\\nJmin = 1\\nJmax = 1000\\nS1 = 0\\nS2 = 0\\nH1 = 0\\nH2 = 0\\nH3 = 0\\nH4 = 0\\n\\n[Peer]\\nPublicKey = {peer_data['client_pub_key']}\\nPresharedKey = {peer_data['preshared_key']}\\nAllowedIPs = 0.0.0.0/0, ::/0\\nEndpoint = {peer_data['hostName']}:{peer_data['port']}\\nPersistentKeepalive = 25\\n",
        "hostName": "{peer_data['hostName']}",
        "port": {peer_data['port']},
        "psk_key": "{peer_data['preshared_key']}",
        "server_pub_key": "{peer_data['client_pub_key']}"
    }}
    '''

    json_value = {
        "containers": [
            {
                "awg": {
                    "H1": "0",
                    "H2": "0",
                    "H3": "0",
                    "H4": "0",
                    "Jc": "2",
                    "Jmax": "1000",
                    "Jmin": "1",
                    "S1": "0",
                    "S2": "0",
                    "last_config": last_config,
                    "port": f"{peer_data['port']}",
                    "transport_proto": "udp"
                },
                "container": "amnezia-awg"
            }
        ],
        "defaultContainer": "amnezia-awg",
        "description": f"{peer_data['description']}",
        "dns1": "1.1.1.1",
        "dns2": "1.0.0.1",
        "hostName": f"{peer_data['description']}"
    }
    return str(json_value)


start()
