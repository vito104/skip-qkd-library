import pytest
from unittest.mock import Mock, patch, MagicMock
from skip_qkd import SkipQKDClient, PSKConfig, MTLSConfig
import json


class TestSkipQKDClientInit:
    def test_init_with_psk(self):
        """Inicializace s PSK"""
        psk = PSKConfig(identity="test", psk="secret")
        client = SkipQKDClient(
            server_address="127.0.0.1:443",
            server_id="server1",
            psk_config=psk
        )
        assert client.server_address == "127.0.0.1:443"
        assert client.server_id == "server1"
        assert client.psk_config == psk

    def test_init_with_mtls(self):
        """Inicializace s mTLS"""
        mtls = MTLSConfig(ca_file="ca.crt", cert_file="cert.crt", key_file="key.key")
        client = SkipQKDClient(
            server_address="127.0.0.1:443",
            server_id="server1",
            mtls_config=mtls
        )
        assert client.mtls_config == mtls

    def test_init_no_config(self):
        """Error - žádná konfigurace"""
        with pytest.raises(ValueError, match="Either mTLS or PSK"):
            client = SkipQKDClient(
                server_address="127.0.0.1:443",
                server_id="server1"
            )
            client._create_tls_connection()


class TestSkipQKDClientRequests:
    def test_capabilities(self):
        """capabilities() - vrací dict s JSON"""
        psk = PSKConfig(identity="test", psk="secret")
        client = SkipQKDClient(
            server_address="127.0.0.1:443",
            server_id="server1",
            psk_config=psk
        )
        
        # ✅ Raw response s chunked encoding
        mock_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Connection: close\r\n"
            b"Content-Type: application/json\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"43\r\n"
            b'{"entropy":false,"key":true,"algorithm":"QKD"}\r\n'
            b"0\r\n"
            b"\r\n"
        )
        
        mock_socket = MagicMock()
        mock_socket.recv.side_effect = [mock_response, b""]
        
        with patch.object(client, '_get_connection', return_value=mock_socket):
            response = client.capabilities()
            # ✅ Vrací dict!
            assert isinstance(response, dict)
            assert response["algorithm"] == "QKD"
            assert response["key"] == True

    def test_request_key_with_peer(self):
        """request_key() - s peer_server_id"""
        psk = PSKConfig(identity="test", psk="secret")
        client = SkipQKDClient(
            server_address="127.0.0.1:443",
            server_id="server1",
            psk_config=psk
        )
        
        mock_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"\r\n"
            b"75\r\n"
            b'{"keyId":"ABC123","key":"DEF456"}\r\n'
            b"0\r\n"
            b"\r\n"
        )
        
        mock_socket = MagicMock()
        mock_socket.recv.side_effect = [mock_response, b""]
        
        with patch.object(client, '_get_connection', return_value=mock_socket):
            response = client.request_key("peer_server")
            # ✅ Bytes, ne string!
            assert b"remoteSystemID=peer_server" in mock_socket.sendall.call_args[0][0]
            assert response["keyId"] == "ABC123"

    def test_request_key_with_size(self):
        """request_key() - s size parametrem"""
        psk = PSKConfig(identity="test", psk="secret")
        client = SkipQKDClient(
            server_address="127.0.0.1:443",
            server_id="server1",
            psk_config=psk
        )
        
        mock_socket = MagicMock()
        mock_socket.recv.side_effect = [b"HTTP/1.1 200 OK\r\n\r\n{}", b""]
        
        with patch.object(client, '_get_connection', return_value=mock_socket):
            client.request_key("peer_server", size=256)
            # ✅ Kontroluj že se poslala správná query
            call_args = mock_socket.sendall.call_args[0][0]
            assert b"size=256" in call_args
            assert b"remoteSystemID=peer_server" in call_args

    def test_fetch_key_by_id(self):
        """fetch_key_by_id()"""
        psk = PSKConfig(identity="test", psk="secret")
        client = SkipQKDClient(
            server_address="127.0.0.1:443",
            server_id="server1",
            psk_config=psk
        )
        
        mock_response = b"HTTP/1.1 200 OK\r\n\r\n" + json.dumps({
            "keyId": "key123",
            "key": "ABC123"
        }).encode()
        
        mock_socket = MagicMock()
        mock_socket.recv.side_effect = [mock_response, b""]
        
        with patch.object(client, '_get_connection', return_value=mock_socket):
            response = client.fetch_key_by_id("key123", "peer_server")
            assert b"/key/key123" in mock_socket.sendall.call_args[0][0]
            assert response["keyId"] == "key123"

    def test_entropy(self):
        """entropy()"""
        psk = PSKConfig(identity="test", psk="secret")
        client = SkipQKDClient(
            server_address="127.0.0.1:443",
            server_id="server1",
            psk_config=psk
        )
        
        mock_socket = MagicMock()
        mock_socket.recv.side_effect = [b"HTTP/1.1 200 OK\r\n\r\n{}", b""]
        
        with patch.object(client, '_get_connection', return_value=mock_socket):
            client.entropy(minentropy=128)
            assert b"minentropy=128" in mock_socket.sendall.call_args[0][0]