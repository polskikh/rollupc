import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from eth_utils.address import to_checksum_address
from eth_utils.crypto import keccak

from rollupc.providers.aws_kms import retrieve_eth_address_from_public_key


@pytest.mark.parametrize(
    "kms_public_key, expected_eth_address",
    [
        (
            b"0V0\x10\x06\x07*\x86H\xce=\x02\x01\x06\x05+\x81\x04\x00\n\x03B\x00\x04"
            b"\x1eP\xed\xf2\xaaXrA\xc4\x83\x9b\x9f\xab\x108*\xfeb@\xd5p\x8a7\x06S9"
            b"\x8b\xb8\xcc\xf9\xb1\xd8\xfd8\x93V3r\xfc\xa7\x00\xd0\xcd\xe9\x95\x01"
            b"\x18v[\xb4\xa9\xddSg\xa4\xc2\x02\x1b\x94\xfa\xef\xc1\\$",
            "0xc5934b8735310C385147771A206Ce6F9bC42aa69",
        ),
        (
            b"0V0\x10\x06\x07*\x86H\xce=\x02\x01\x06\x05+\x81\x04\x00\n\x03B\x00\x04"
            b"\x9e\x16.\xf4\xda\xd8R \x11\xf3\x90sh\xd4o\xa3\xa1)\xd4x\r\xe0\x162\xf6"
            b"\xb7<\xcd\xac1#\x97e\x05B8\x9b\x87\xbb\xa5\xfdA\x0e:x\xef\x97\xbf\x17`\n"
            b"\xa4\x0e!yL\x95\xfaxG\xe5\xcbb\x9d",
            "0xbb4f9dE3B09F99176750fEd1FcBDc94bA5bb7796",
        ),
    ],
)
def test_retrieve_eth_address_from_public_key_known_keys(kms_public_key: bytes, expected_eth_address: str):
    eth_address = retrieve_eth_address_from_public_key(kms_public_key)

    assert eth_address == expected_eth_address


def test_retrieve_eth_address_from_public_key():
    pk = ec.generate_private_key(ec.SECP256K1())
    pub_key = pk.public_key()

    der_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    uncompressed = pub_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    expected_address = to_checksum_address(keccak(uncompressed[1:])[-20:])

    eth_address = retrieve_eth_address_from_public_key(der_bytes)

    assert eth_address == expected_address
