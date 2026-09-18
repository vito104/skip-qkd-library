# skip-qkd

Python client library for the SKIP (Secure Key Integration Protocol) - a protocol for QKD Key Providers.

## Features

- **mTLS Authentication**: Secure certificate-based authentication
- **PSK Authentication**: Pre-shared key based authentication  
- **Key Management**: Dynamic key provisioning and retrieval
- **Entropy Support**: Random data generation from Key Providers (MUST BE SUPPORTED BY THE KEY PROVIDER!)

## Installation

```bash
pip install skip-qkd
```

## Quick Start

### mTLS Example

```python
from skip_qkd import SkipQKDClient, MTLSConfig

# Configure mTLS
mtls = MTLSConfig(
    ca_file="/path/to/ca.crt",
    cert_file="/path/to/client.crt",
    key_file="/path/to/client.key"
)

# Create client
client = SkipQKDClient(
    server_address="qkd.example.com:8200",
    server_id="my_system",
    mtls_config=mtls
)

# Get server capabilities
caps = client.capabilities()
print(caps)

# Request a key from peer system
key_response = client.request_key(peer_server_id="peer_system")
print(f"Key ID: {key_response['keyId']}")
print(f"Key: {key_response['key']}")

client.close()
```

### PSK Example

```python
from skip_qkd import SkipQKDClient, PSKConfig

# Configure PSK
psk = PSKConfig(
    identity="my_identity",
    psk="my_secret_psk_key"
)

# Create client
client = SkipQKDClient(
    server_address="qkd.example.com:443",
    server_id="my_system",
    psk_config=psk
)

# Use with context manager (auto-closes)
with SkipQKDClient(
    server_address="qkd.example.com:8200",
    server_id="my_system",
    psk_config=psk
) as client:
    response = client.request_key("peer_system")
    print(response["key"])
```

## API Reference

### SkipQKDClient

Main class for interacting with SKIP Key Providers.

#### Constructor

```python
SkipQKDClient(
    server_address: str,
    server_id: str,
    mtls_config: MTLSConfig = None,
    psk_config: PSKConfig = None
)
```

**Parameters:**
- `server_address` (str): Server host and port in format "host:port"
- `server_id` (str): Identifier for your system (included in HTTP Host header)
- `mtls_config` (MTLSConfig): mTLS configuration (*optional)
- `psk_config` (PSKConfig): PSK configuration (*optional)
(*) At least one of `mtls_config` or `psk_config` must be provided.

**Raises:**
- `ValueError`: If neither mTLS nor PSK configuration is provided

#### Methods

##### capabilities()

Get the capabilities of the Key Provider.

```python
response = client.capabilities()
# Returns: {
#     "entropy": bool,
#     "key": bool,
#     "algorithm": str,
#     "localSystemID": str,
#     "remoteSystemID": [str, ...]
# }
```

##### request_key(peer_server_id, size=None)

Request a new key for communication with a peer system.

```python
response = client.request_key("peer_system")
# Returns: {"keyId": str, "key": str}

# With specific key size (in bits)
response = client.request_key("peer_system", size=256)
```

**Parameters:**
- `peer_server_id` (str): ID of the peer system
- `size` (int, optional): Key size in bits

##### fetch_key_by_id(key_id, peer_server_id)

Retrieve a previously generated key by its ID.

```python
response = client.fetch_key_by_id("key_id_here", "peer_system")
# Returns: {"keyId": str, "key": str}
```

**Parameters:**
- `key_id` (str): The key identifier
- `peer_server_id` (str): ID of the peer system

##### entropy(minentropy=None)

Get random data from the Key Provider.

```python
response = client.entropy()
# Returns: {"randomStr": str, "minentropy": int}

# With specific entropy size (in bits)
response = client.entropy(minentropy=128)
```

**Parameters:**
- `minentropy` (int, optional): Requested entropy size in bits

##### close()

Close the TLS connection.

```python
client.close()
```

### Configuration Classes

#### MTLSConfig

mTLS (mutual TLS) configuration for certificate-based authentication.

```python
from skip_qkd import MTLSConfig

mtls = MTLSConfig(
    ca_file="/path/to/ca.crt",
    cert_file="/path/to/client.crt",
    key_file="/path/to/client.key"
)
```

**Attributes:**
- `ca_file` (str): Path to CA certificate file
- `cert_file` (str): Path to client certificate file
- `key_file` (str): Path to client private key file

#### PSKConfig

PSK (Pre-Shared Key) configuration for key-based authentication.

```python
from skip_qkd import PSKConfig

psk = PSKConfig(
    identity="my_identity",
    psk="my_secret_key"
)
```

**Attributes:**
- `identity` (str): PSK identity/label
- `psk` (str): Pre-shared key value

## Examples

### Key Exchange Between Systems

```python
from skip_qkd import SkipQKDClient, MTLSConfig

# System A: Request a key
mtls_a = MTLSConfig(
    ca_file="certs/ca.crt",
    cert_file="certs/a_cert.crt",
    key_file="certs/a_key.key"
)

client_a = SkipQKDClient(
    server_address="kp-a.example.com:443",
    server_id="SystemA",
    mtls_config=mtls_a
)

key_response = client_a.request_key("SystemB")
key_id = key_response["keyId"]
key = key_response["key"]

print(f"Share this keyId with SystemB: {key_id}")
client_a.close()

# System B: Retrieve the key
mtls_b = MTLSConfig(
    ca_file="certs/ca.crt",
    cert_file="certs/b_cert.crt",
    key_file="certs/b_key.key"
)

client_b = SkipQKDClient(
    server_address="kp-b.example.com:443",
    server_id="SystemB",
    mtls_config=mtls_b
)

key_response = client_b.fetch_key_by_id(key_id, "SystemA")
retrieved_key = key_response["key"]

assert key == retrieved_key  # Keys should match!
client_b.close()
```

## Security Considerations

- Always use TLS 1.2 or higher
- mTLS is recommended for certificate-based authentication
- PSK-based authentication is believed to be quantum-resistant
- Keep Key Provider and encryptor co-located when possible
- Use network segmentation to protect the KP-encryptor link
- Keys are one-time use - they are zeroized after retrieval

## Requirements

- Python 3.8+
- sslpsk3 >= 0.0.1

## Testing

Run the test suite:

```bash
pytest tests/ -v
```

Run with coverage:

```bash
pytest tests/ --cov=skip_qkd
```

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

## Tested On

- Python 3.14.4 on Linux (Ubuntu 26.04.1 LTS)

Note: While this library targets Python 3.8+, it has only been tested on Python 3.11.

## Author

**Vit Ruzicka**  
Department of Information Systems  
Faculty of Information Technology  
Brno University of Technology

## License

MIT License - see LICENSE file for details

## References

- [IETF Draft - Secure Key Integration Protocol (SKIP)](https://www.ietf.org/archive/id/draft-cisco-skip-00.txt)
