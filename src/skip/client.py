from dataclasses import dataclass
import socket
import ssl
from sslpsk3 import SSLPSKContext


@dataclass
class MTLSConfig:
    ca_file: str
    cert_file: str
    key_file: str

    def __post_init__(self):
        if not all([self.ca_file, self.cert_file, self.key_file]):
            raise ValueError("MTLSConfig: All fields (ca_file, cert_file, key_file) must be provided.")

@dataclass
class PSKConfig:
    identity: str
    psk: str

    def __post_init__(self):
        if not all([self.identity, self.psk]):
            raise ValueError("PSKConfig: Both identity and psk must be provided.")

        
class SkipQKDClient:

    def close(self):
        if self.socket:
            self.socket.close()
            self.socket = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


    def _create_tls_connection(self):
        host, port = self.server_address.split(':')
        raw_socket = socket.create_connection((host, int(port)))
        
        if not self.mtls_config and not self.psk_config:
            raise ValueError("Either mTLS or PSK configuration must be provided.")
        
        def psk_callback(hint):
            return self.psk_config.identity, self.psk_config.psk
        
        if self.mtls_config and self.psk_config:
            context = SSLPSKContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED  
            context.load_verify_locations(cafile=self.mtls_config.ca_file)
            context.load_cert_chain(certfile=self.mtls_config.cert_file, keyfile=self.mtls_config.key_file)
            context.set_psk_client_callback(psk_callback)
        
        elif self.psk_config:
            context = SSLPSKContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_NONE
            context.maximum_version = ssl.TLSVersion.TLSv1_2
            context.set_ciphers("PSK")
            context.set_psk_client_callback(psk_callback)
        
        elif self.mtls_config:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(cafile=self.mtls_config.ca_file)
            context.load_cert_chain(certfile=self.mtls_config.cert_file, keyfile=self.mtls_config.key_file)
        
        return context.wrap_socket(raw_socket)

    def close(self):
        if self.socket:
            self.socket.close()
            self.socket = None

    def __init__(self, server_address: str, server_id: str, mtls_config: MTLSConfig = None, psk_config: PSKConfig = None):
        self.server_address = server_address
        self.server_id = server_id
        self.mtls_config = mtls_config
        self.psk_config = psk_config
        self.socket = None 

    def _get_connection(self):
        if self.socket is None:
            self.socket = self._create_tls_connection()
        return self.socket

    def _send_request(self, method: str, path: str, query_params: dict = None) -> str:
        """Posílá HTTP request s query parametry"""
        if query_params is None:
            query_params = {}
        
        full_path = path
        if query_params:
            query_string = '&'.join(f"{k}={v}" for k, v in query_params.items())
            full_path = f"{path}?{query_string}"
        
        http_request = f"{method} {full_path} HTTP/1.1\r\nHost: {self.server_id}\r\nConnection: close\r\n\r\n"
        socket = self._get_connection()
        socket.sendall(http_request.encode())
        
        response = b""
        while True:
            data = socket.recv(4096)
            if not data:
                break
            response += data
        
        return response.decode(errors='replace')


    def request_key(self, peer_server_id: str, size: int = None) -> str:
        params = {'remoteSystemID': peer_server_id}
        if size:
            params['size'] = size
        return self._send_request("GET", "/key", params)

    def fetch_key_by_id(self, key_id: str, peer_server_id: str) -> str:
        params = {'remoteSystemID': peer_server_id}
        return self._send_request("GET", f"/key/{key_id}", params)

    def capabilities(self) -> str:
        return self._send_request("GET", "/capabilities")

    def entropy(self, minentropy: int = None) -> str:
        params = {}
        if minentropy:
            params['minentropy'] = minentropy
        return self._send_request("GET", "/entropy", params)