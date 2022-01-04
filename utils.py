import base64
from typing import Dict, Generic, Optional, TypeVar, Type, Union

import rsa


KEY_TYPES = TypeVar("KEY_TYPES", rsa.PublicKey, rsa.PrivateKey)


def get_new_keys(*args, **kwargs):
    pubkey, privkey = rsa.newkeys(*args, **kwargs)
    return {
        "pubkey": KeyWrapper[rsa.PublicKey](value=pubkey),
        "privkey": KeyWrapper[rsa.PrivateKey](value=privkey)
    }


class KeyWrapper(Generic[KEY_TYPES]):

    def __init__(self, value: KEY_TYPES):
        self.value = value

    def to_dict(self) -> Dict:
        return {
            attr: getattr(self.value, attr)
            for attr in dir(self.value)
            if len(attr) == 1
        }

    @classmethod
    def from_dict(
            cls,
            dictionary: Dict,
            class_reference: Union[Type[rsa.PublicKey], Type[rsa.PrivateKey]]
    ) -> 'KeyWrapper':
        return cls(value=class_reference(**{key: val if isinstance(val, str) else int(val) for key, val in dictionary.items()}))

    @classmethod
    def from_pubdict(cls, dictionary: Dict) -> 'KeyWrapper[rsa.PublicKey]':
        return cls(value=rsa.PublicKey(**dictionary))

    @classmethod
    def from_privdict(cls, dictionary) -> 'KeyWrapper[rsa.PrivateKey]':
        return cls(value=rsa.PrivateKey(**dictionary))


def rsa_encrypt(message: str, pubkey: KeyWrapper[rsa.PublicKey], encoding: str = "utf-8"):
    return base64.b64encode(rsa.encrypt(message.encode(encoding), pubkey.value)).decode(encoding)


def rsa_decrypt(message: str, privkey: KeyWrapper[rsa.PrivateKey], encoding: str = "utf-8"):
    return rsa.decrypt(base64.b64decode(message.encode(encoding)), privkey.value).decode(encoding)


class RSAEncryption:

    def __init__(
            self,
            pubkey: KeyWrapper[rsa.PublicKey],
            privkey: KeyWrapper[rsa.PrivateKey],
            encoding: Optional[str] = None
    ):
        if not encoding:
            encoding = "utf-8"
        self.pubkey = pubkey
        self.privkey = privkey
        self.encoding = encoding

    def encrypt(self, message: str) -> str:
        return rsa_encrypt(message=message, pubkey=self.pubkey, encoding=self.encoding)

    def decrypt(self, message: str) -> str:
        return rsa_decrypt(message=message, privkey=self.privkey, encoding=self.encoding)

    @staticmethod
    def new(nbits: int, *args, **kwargs) -> 'RSAEncryption':
        return RSAEncryption(**get_new_keys(nbits=nbits, *args, **kwargs))

