from abc import ABC, abstractmethod


class KeyProvider(ABC):
    @abstractmethod
    def get_public_key(self) -> str:
        """Retrieve the public key."""
        pass
