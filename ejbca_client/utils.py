from typing import Optional
from dataclasses import dataclass

import OpenSSL.crypto


@dataclass
class SubjectDN:
    cn: str
    surname: Optional[str] = None
    givenName: Optional[str] = None
    t: Optional[str] = None
    ou: Optional[str] = None
    o: Optional[str] = None
    l: Optional[str] = None
    st: Optional[str] = None
    street: Optional[str] = None

    def __str__(self):
        result = []
        for name, _ in self.__annotations__.items():
            value = getattr(self, name)
            if value is None:
                continue
            result.append(f"{name.upper()}={value}")
        return ", ".join(result)


def cert_pem_extract_serial(cert: str) -> str:
    cert_obj = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM, cert)
    return "{:x}".format(cert_obj.get_serial_number())
