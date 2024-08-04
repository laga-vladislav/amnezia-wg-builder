from os import system, name
from typing import TypedDict
from core import pack
import json


def clear():
    """clears the terminal"""
    system('cls' if name == 'nt' else 'clear')


class WireguardConfInterfaceData(TypedDict):
    """
    the interface parameters from wireguard .conf file
    """
    PrivateKey: str
    Address: str
    DNS: str


class WireguardConfAdditionalInterfaceData(WireguardConfInterfaceData):
    """
    additional parameters used by the amnezia-wg protocol
    """
    Jc: int
    Jmin: int
    Jmax: int
    S1: int
    S2: int
    H1: int
    H2: int
    H3: int
    H4: int


class WireguardConfPeerData(TypedDict):
    """
    the peer parameters from wireguard .conf file
    """
    PublicKey: str
    PresharedKey: str
    AllowedIPs: str
    Endpoint: str
    Port: str


class WireguardConfFullData(TypedDict):
    Interface: WireguardConfInterfaceData
    Peer: WireguardConfPeerData


class WireguardConfParser:
    """
    .conf file parser
    """
    def __init__(self, conf_file: str):
        self.CONF_FILE = conf_file

    def read_data(self) -> str:
        """return a string with all the data from .conf file"""
        with open(self.CONF_FILE, 'r') as file:
            lines = file.readlines()
        return "".join(lines)

    def pack_config_data(self) -> WireguardConfFullData:
        """return packed data from .conf file

        packed date is an instance of WireguardConfFullData
        """
        wireguard_data: WireguardConfFullData = {}
        interface_data: WireguardConfInterfaceData = {}
        peer_data: WireguardConfPeerData = {}
        data = self.read_data()
        parsing_mode = ""

        for line in data.split('\n'):
            if line == '[Interface]':
                parsing_mode = 'interface'
                continue
            elif line == '[Peer]':
                parsing_mode = 'peer'
                continue

            line_list = [l.strip() for l in line.split('=', 1)]
            if line_list == ['']:
                continue

            if parsing_mode == 'interface':
                interface_data[line_list[0]] = line_list[1]
            if parsing_mode == 'peer':
                peer_data[line_list[0]] = line_list[1]

        wireguard_data['Interface'] = interface_data
        wireguard_data['Peer'] = peer_data

        return wireguard_data


def unpack_config_data(packed_config_data: WireguardConfFullData) -> str:
    """return string with the unpacked data from WireguardConfFullData instance"""
    data = ['[Interface]']

    for interface_key in packed_config_data['Interface']:
        value = packed_config_data['Interface'][interface_key]

        if interface_key == 'Address':
            value = value.split(',')[0]
        if interface_key == 'DNS':
            value = '$PRIMARY_DNS, $SECONDARY_DNS'

        data.append(f"{interface_key} = {value}")

    data.append('\n[Peer]')
    for peer_key in packed_config_data['Peer']:
        value = packed_config_data['Peer'][peer_key]
        data.append(f"{peer_key} = {value}")

    return "\n".join(data)


def add_parameters_in_config_data(packed_config_data: WireguardConfFullData):
    """updates packed data which is th instance of WireguardConfFullData

    more specifically data is the instance of WireguardConfAdditionalInterfaceData
    """
    additional_parameters: WireguardConfAdditionalInterfaceData = {
        'Jc': '2',
        'Jmin': '1',
        'Jmax': '1000',
        'S1': '0',
        'S2': '0',
        'H1': '0',
        'H2': '0',
        'H3': '0',
        'H4': '0'
    }

    packed_config_data['Interface'].update(additional_parameters)


class AmneziaWgBuilder:
    """
    this class helps to encode (build) data from WireguardConfFullData instance
    """
    def __init__(self, wireguard_config_data: WireguardConfFullData, description: str):
        self.WIREGUARD_CONFIG_DATA = wireguard_config_data
        self.DESCRIPTION = description

    def build(self):
        """this method encodes information"""
        json_data = self.generate_json()
        print(pack(json_data))

    def get_string_wireguard_config_data(self):
        add_parameters_in_config_data(self.WIREGUARD_CONFIG_DATA.copy())
        return unpack_config_data(self.WIREGUARD_CONFIG_DATA).replace('\n', '\\n')

    def get_client_ip(self) -> str:
        return self.WIREGUARD_CONFIG_DATA["Interface"]["Address"].split(",")[0].split('/')[0]

    def generate_json(self) -> str:
        client_ip = self.get_client_ip()
        client_priv_key = self.WIREGUARD_CONFIG_DATA['Interface']['PrivateKey']
        config = self.get_string_wireguard_config_data()
        hostName, port = self.WIREGUARD_CONFIG_DATA['Peer']['Endpoint'].split(':')
        psk_key = self.WIREGUARD_CONFIG_DATA['Peer']["PresharedKey"]
        server_pub_key = self.WIREGUARD_CONFIG_DATA['Peer']['PublicKey']
        PRIMARY_DNS, SECONDARY_DNS = self.WIREGUARD_CONFIG_DATA['Interface']['DNS'].split(',')
        last_config = (
            '{\n'
            '    "H1": "0",\n'
            '    "H2": "0",\n'
            '    "H3": "0",\n'
            '    "H4": "0",\n'
            '    "Jc": "2",\n'
            '    "Jmax": "1000",\n'
            '    "Jmin": "1",\n'
            '    "S1": "0",\n'
            '    "S2": "0",\n'
            f'    "client_ip": "{client_ip}",\n'
            f'    "client_priv_key": "{client_priv_key}",\n'
            f'    "client_pub_key": "0",\n'
            f'    "config": "{config}",\n'
            f'    "hostName": "{hostName}",\n'
            f'    "port": {port},\n'
            f'    "psk_key": "{psk_key}",\n'
            f'    "server_pub_key": "{server_pub_key}"\n'
            '}\n'
        )

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
                        "last_config": f'{last_config}',
                        "port": f"{port}",
                        "transport_proto": "udp"
                    },
                    "container": "amnezia-awg"
                }
            ],
            "defaultContainer": "amnezia-awg",
            "description": f"{self.DESCRIPTION}",
            "dns1": f"{PRIMARY_DNS}",
            "dns2": f"{SECONDARY_DNS}",
            "hostName": f"{hostName}"
        }
        return json.dumps(json_value)


class AmneziaWgDialogueStateMachine:
    def __init__(self):
        self.AmneziaWgBuilder: AmneziaWgBuilder = None
        self.WireguardConfParser: WireguardConfParser = None
        self.state: str = 'start'
        self.data: str = ""
        self.wireguard_cong_file: str = ""

    def start(self):
        print("Welcome! Please choose an option:")
        print("1 — get data from wireguard configuration file\n2 — insert data in terminal")
        choice = input("Enter your choice: ")
        if choice == '1':
            self.state = 'conf_file'
        elif choice == '2':
            self.state = 'manual_input'
        clear()

    def conf_file(self):
        try:
            self.data = self.get_data_from_conf()
            if self.data is None:
                return
            self.state = "conf_file_accepted"
        except Exception as e:
            print(e)
            self.state = 'conf_file'

    def manual_input(self):
        print("sorry, this mode is not available right now")
        self.state = 'start'

    def get_data_from_conf(self) -> str | None:
        files = self.get_wireguard_conf_files()
        if not files:
            print('Sorry, but no .conf files were found')
            self.state = 'end'
            return None

        for index, file in enumerate(files):
            print(f"{index + 1}. {file}")
        ans = input("file number: ")
        print(f"You entered: {ans}")
        if ans not in [str(i + 1) for i in range(len(files))]:
            raise Exception

        self.wireguard_cong_file = files[int(ans) - 1]
        data = self.read_conf_file(self.wireguard_cong_file)
        clear()

        return data

    @staticmethod
    def get_wireguard_conf_files() -> list[str]:
        import os
        files = []
        for file in os.listdir():
            if file.endswith(".conf"):
                files.append(file)
        return files

    def read_conf_file(self, conf_file: str) -> str:
        conf_packed_data = self.get_packed_data(conf_file)

        conf_data = self.get_conf_data(conf_packed_data)

        return conf_data

    def get_packed_data(self, conf_file: str) -> WireguardConfFullData:
        self.WireguardConfParser = WireguardConfParser(conf_file)
        return self.WireguardConfParser.pack_config_data()

    def get_conf_data(self, conf_packed_data: WireguardConfFullData) -> str:
        conf_filename = self.wireguard_cong_file.split('.')[0]
        self.AmneziaWgBuilder = AmneziaWgBuilder(conf_packed_data, conf_filename)
        return self.AmneziaWgBuilder.get_string_wireguard_config_data()

    def run(self):
        while True:
            getattr(self, self.state)()

    def conf_file_accepted(self):
        self.state = 'end'
        return self.AmneziaWgBuilder.build()

    @staticmethod
    def end():
        exit(0)


class App:
    @staticmethod
    def start() -> None:
        sm = AmneziaWgDialogueStateMachine()
        sm.run()


if __name__ == '__main__':
    App().start()
