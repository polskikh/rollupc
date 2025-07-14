import logging
import boto3
from botocore.exceptions import NoCredentialsError
from rollupc.providers.base import KeyProvider
from rollupc.exceptions import RollupCException
from cryptography.hazmat.primitives import serialization
from eth_utils.crypto import keccak
from eth_utils.address import to_checksum_address

logger = logging.getLogger(__name__)


class AWSKMSProvider(KeyProvider):
    def __init__(self, key_id: str):
        self._check_identity()
        self.kms = boto3.client("kms")
        self.key_id = key_id

    def get_public_key(self) -> str:
        """Retrieve the public key from AWS KMS."""
        logger.info(f"Retrieving public key for KMS key ID: {self.key_id}")
        try:
            public_key_bytes = self.kms.get_public_key(KeyId=self.key_id)["PublicKey"]
            eth_address = self._retrieve_eth_address_from_public_key(public_key_bytes)
        except Exception as e:
            logger.error(f"Failed to retrieve public key: {e}")
            raise RollupCException("Failed to retrieve public key") from e

        return eth_address

    def _check_identity(self):
        try:
            sts = boto3.client("sts")
            identity = sts.get_caller_identity()
            logger.info(f"Using AWS KMS with user: {identity['Arn']}")
            logger.debug(identity)
        except NoCredentialsError as e:
            logger.error(f"Failed to get AWS account identity: {e}")
            raise RollupCException("Failed to get AWS account identity") from e

    def _retrieve_eth_address_from_public_key(self, public_key_bytes: bytes) -> str:
        public_key = serialization.load_der_public_key(public_key_bytes)
        uncompressed = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        eth_address = to_checksum_address(keccak(uncompressed[1:])[-20:])
        return eth_address
