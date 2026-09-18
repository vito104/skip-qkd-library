import pytest
from skip_qkd import PSKConfig, MTLSConfig


class TestPSKConfig:
    def test_valid_psk_config(self):
        """PSKConfig s správnými hodnotami"""
        config = PSKConfig(identity="test_id", psk="test_psk")
        assert config.identity == "test_id"
        assert config.psk == "test_psk"

    def test_psk_config_missing_identity(self):
        """PSKConfig - chybí identity"""
        with pytest.raises(ValueError, match="Both identity and psk"):
            PSKConfig(identity="", psk="test_psk")

    def test_psk_config_missing_psk(self):
        """PSKConfig - chybí psk"""
        with pytest.raises(ValueError, match="Both identity and psk"):
            PSKConfig(identity="test_id", psk="")

    def test_psk_config_both_missing(self):
        """PSKConfig - chybí oba"""
        with pytest.raises(ValueError):
            PSKConfig(identity="", psk="")


class TestMTLSConfig:
    def test_valid_mtls_config(self):
        """MTLSConfig s správnými hodnotami"""
        config = MTLSConfig(ca_file="ca.crt", cert_file="cert.crt", key_file="key.key")
        assert config.ca_file == "ca.crt"
        assert config.cert_file == "cert.crt"
        assert config.key_file == "key.key"

    def test_mtls_config_missing_ca_file(self):
        """MTLSConfig - chybí ca_file"""
        with pytest.raises(ValueError, match="All fields"):
            MTLSConfig(ca_file="", cert_file="cert.crt", key_file="key.key")

    def test_mtls_config_missing_cert_file(self):
        """MTLSConfig - chybí cert_file"""
        with pytest.raises(ValueError, match="All fields"):
            MTLSConfig(ca_file="ca.crt", cert_file="", key_file="key.key")

    def test_mtls_config_all_missing(self):
        """MTLSConfig - chybí všechno"""
        with pytest.raises(ValueError):
            MTLSConfig(ca_file="", cert_file="", key_file="")