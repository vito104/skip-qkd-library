from skip_qkd import SkipQKDClient, PSKConfig, MTLSConfig



client = SkipQKDClient(
    server_address="skip.example.com:443",
    server_id="my_system",
    
)

# 1. Stáhni capabilities
try:
    response = client.capabilities()
    print("Capabilities:", response)
except Exception as e:
    print("Error:", e)
