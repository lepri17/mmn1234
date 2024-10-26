import struct

class Request:
    def __init__(self, client_id, version, code, payload_size, payload):
        self.client_id = client_id
        self.version = version
        self.code = code
        self.payload_size = payload_size
        self.payload = payload

def parse_request(data):
    client_id = data[:16]  # .decode('utf-8').rstrip('\x00')
    version = struct.unpack('B', data[16:17])[0]
    code = struct.unpack('!H', data[18:20])[0]
    print(f"in mddle Client ID: {client_id}, Version: {version}, Code: {code}")
    payload_size = struct.unpack('!I', data[20:24])[0]
    if code != 828:
        payload = data[24:24 + payload_size].decode('utf-8')
    else:
        payload = data[24:24 + payload_size]
    print(f"Client ID: {client_id}, Version: {version}, Code: {code}, Payload size: {payload_size}")
    return Request(client_id, version, code, payload_size, payload)





