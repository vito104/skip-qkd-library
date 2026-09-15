import pytest
from skip_qkd import SkipQKDClient, PSKConfig, MTLSConfig
from unittest.mock import Mock, patch, MagicMock

class TestSkipQKDClientInit:
    def test_init_with_psk(self):
        psk = PSKConfig(identity="test_identity", psk="test_key")
        client = SkipQKDClient(server_address="127.0.0.1:8000", server_id="test_client", psk_config=psk)
        assert client.server_address == "127.0.0.1:8000"
        assert client.server_id == "test_client"
        assert client.psk_config == psk


    def test_init_with_mtls(self):
        mtls = MTLSConfig(cert_file="cert.pem", key_file="key.pem", ca_file="ca.pem")
        client = SkipQKDClient(server_address="127.0.0.1:8000", server_id="test_client", mtls_config=mtls)
        assert client.mtls_config == mtls

    def test_init_no_data(self):
        with pytest.raises(ValueError, match="Either mTLS or PSK configuration must be provided."):
            client = SkipQKDClient(server_address="127.0.0.1:8000", server_id="test_client")
            client._create_tls_connection()

class TestSkipQKDClientRequests:

    @patch('socket.socket')
    def test_send_request_basic(self, mock_socket):
        psk = PSKConfig(identity="test", psk="secret")
        client = SkipQKDClient(
            server_address="127.0.0.1:8000",
            server_id="server1",
            psk_config=psk
        )

    def test_request_key_with_peer(self):
        psk = PSKConfig(identity="test", psk="secret")
        client = SkipQKDClient(
            server_address="127.0.0.1:8000",
            server_id="server1",
            psk_config=psk
        )

        mock_socket = MagicMock()
        mock_socket.recv.side_effect = [b"HTTP/1.1 200 OK\r\n\r\n{}", b""]

        with patch.object(client, '_get_connection', return_value=mock_socket):
            response = client.request_key("peer_server")
            assert b"remoteSystemID=peer_server" in mock_socket.sendall.call_args[0][0]


    def test_capabilities(self):
        psk = PSKConfig(identity="test", psk="secret")
        client = SkipQKDClient(
            server_address="127.0.0.1:8000",
            server_id="server1",
            psk_config=psk
        )

        mock_socket = MagicMock()
        mock_socket.recv.side_effect = [b"HTTP/1.1 200 OK\r\n\r\n{}", b""]

        with patch.object(client, '_get_connection', return_value=mock_socket):
            response = client.capabilities()
            assert b"/capabilities" in mock_socket.sendall.call_args[0][0]


    def test_entropy_with_minentropy(self):
        psk = PSKConfig(identity="test", psk="secret")
        client = SkipQKDClient(
            server_address="127.0.0.1:8000",
            server_id="server1",
            psk_config=psk
        )

        mock_socket = MagicMock()
        mock_socket.recv.side_effect = [b"HTTP/1.1 200 OK\r\n\r\n{}", b""]

        with patch.object(client, '_get_connection', return_value=mock_socket):
            response = client.entropy(minentropy=128)
            assert b"minentropy=128" in mock_socket.sendall.call_args[0][0]