import configparser
import json
import os
import zlib

import mitmproxy.http
import swmitm.cryptography


class SWProxy:
    def __init__(self):
        print('Created a new SWProxy instance')
        config = configparser.ConfigParser()
        if not config.read('config.ini'):
            raise RuntimeError('config.ini not found')
        self.client_key = None
        self.api_key = bytes.fromhex(config.get('Cryptography', 'api_encryption_key'))
        self.server_pk = bytes.fromhex(config.get('Cryptography', 'server_public_key'))
        self.encryption_header = bytes.fromhex(config.get('Cryptography', 'encryption_header'))
        self.log_file = config.get('Settings', 'log_file_path')

    def request(self, flow: mitmproxy.http.HTTPFlow):
        if flow.request.path == '/api/gateway_c2.php':
            self.on_gateway_request(flow)

    def on_gateway_request(self, flow: mitmproxy.http.HTTPFlow):
        request = flow.request
        content = swmitm.cryptography.decrypt_request(request.content, key=self.api_key)
        if content.get('command') in ['GuestLogin', 'HubUserLogin']:
            if request.headers.get(b'SmonChecker'):
                print('Found SmonChecker in the login request. Not modifying the request')
                return
            if not content.get('sck'):
                print("sck is not in the login request. Perhaps the encryption has changed")
                return
            self.client_key = os.urandom(16)
            content['sck'] = swmitm.cryptography.pk_encrypt(self.client_key, self.server_pk).decode()
            content = swmitm.cryptography.encrypt_request(content, self.api_key)
            request.content = content
            print(f'Using {self.client_key.hex()} as encryption key')

    def response(self, flow: mitmproxy.http.HTTPFlow):
        if flow.request.path == '/api/gateway_c2.php':
            self.on_gateway_response(flow)

    def on_gateway_response(self, flow: mitmproxy.http.HTTPFlow):
        response = flow.response
        content = response.content
        request_dict = swmitm.cryptography.decrypt_request(flow.request.content, key=self.api_key)
        if content.startswith(self.encryption_header):
            if not self.client_key:
                self.log(request_dict, {})
                print("Can't decrypt response without a key. Restart the game to generate a new key")
                return
            content = content[16:]
            content = swmitm.cryptography.decrypt_message(content, self.client_key)
            response_dict = json.loads(zlib.decompress(content))
            content = swmitm.cryptography.encrypt_message(content, self.api_key)
            response.content = content
        else:
            response_dict = swmitm.cryptography.decrypt_response(content, self.api_key)
        self.log(request_dict, response_dict)

    def log(self, request: dict, response: dict):
        with open(self.log_file, 'a+') as file:
            file.write(json.dumps(request))
            file.write('\n\n')
            file.write(json.dumps(response))
            file.write('\n\n\n')
        print(f'Saved {request.get("command")} command data to {self.log_file}')


addons = [SWProxy()]
