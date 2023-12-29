import base64
from pathlib import Path
from typing import Optional, Union, List, Tuple

import zeep
from zeep.transports import Transport
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from .data import (
    UserMatch,
    UserDataVOWS,
    AlgorithmConstants,
    CertificateHelper
)
from .utils import SubjectDN
from .exception import EjbcaClientException


class EjbcaClient:

    _wsdl_path = "/ejbca/ejbcaws/ejbcaws?wsdl"
    _default_end_entity_profile_name = "EMPTY"
    _default_cert_profile_name = "ENDUSER"

    def __init__(
        self,
        base_url: str,
        ca_cert: Optional[Union[str, Path]] = None,
        client_cert: Optional[Union[str, Path]] = None,
        client_key: Optional[Union[str, Path]] = None,
        wsdl_path: Optional[str] = None
    ):
        """
        Args:
            base_url - base url ejbca server, without path
            wsdl_path - if exist, it will be used instead of
                generate from base_url
        """
        if wsdl_path is not None:
            self._url = wsdl_path
        else:
            self._url = f"{base_url}{self._wsdl_path}"

        # config session
        ca_cert = self._check_path(ca_cert)
        client_cert = self._check_path(client_cert)
        client_key = self._check_path(client_key)

        self._session = requests.Session()

        if ca_cert is not None:
            self._session.verify = ca_cert

        if client_cert is not None and client_key is not None:
            self._session.cert = (client_cert, client_key)

        # soap client
        self._client = zeep.Client(
            wsdl=self._url,
            transport=Transport(session=self._session)
        )

    def _check_path(
        self, file_path: Optional[Union[str, Path]] = None
    ) -> str:
        """Check that the file is existed and
        it are returning in format Path
        """
        if file_path is None:
            return
        if isinstance(file_path, str):
            file_path = Path(file_path)
        if not file_path.is_file():
            raise ValueError(f"The {file_path} not exists")
        return str(file_path)

    def find_user_by_dn(self, dn: str) -> List["userDataVOWS"]:
        """
        Raises:
            EjbcaClientException
        """
        try:
            # Type
            userMatch = self._client.get_type(
                "{http://ws.protocol.core.ejbca.org/}userMatch"
            )

            # List of userDataVOWS
            r = self._client.service.findUser(
                userMatch(
                    UserMatch.MATCH_TYPE_CONTAINS.value,
                    dn,
                    UserMatch.MATCH_WITH_DN.value
                )
            )
        except zeep.exceptions.Fault as e:
            raise EjbcaClientException(str(e))
        return r

    def generate_certificate(
        self,
        ca_name: str,
        username: str,
        password: str,
        subject_dn: SubjectDN,
        bits: int = 2048,
        end_entity_profile_name: Optional[str] = None,
        cert_profile_name: Optional[str] = None,
    ) -> Tuple[str, str]:
        """This function create user and it generate for them certificate
        The private key is generated local.

        Args:
            ca_name - Name of CA for the one will be create certificate
            common_name
            private_key, csr - return from generate_csr
            bits - length private key (RSA)

            username
            password
            subjectDN

        Raises:
            EjbcaClientException

        Return
            Certificate in PEM, Private key in PEM
        """
        # Prepea
        if end_entity_profile_name is None:
            end_entity_profile_name = self._default_end_entity_profile_name
        if cert_profile_name is None:
            cert_profile_name = self._default_cert_profile_name

        # Type
        userDataVOWS = self._client.get_type(
            '{http://ws.protocol.core.ejbca.org/}userDataVOWS')

        user = userDataVOWS()

        user.caName = ca_name
        user.username = username
        user.password = password
        user.clearPwd = False
        user.subjectDN = str(subject_dn)

        user.tokenType = UserDataVOWS.TOKEN_TYPE_USERGENERATED
        user.keyRecoverable = False
        user.sendNotification = False
        user.status = UserDataVOWS.STATUS_NEW
        user.endEntityProfileName = end_entity_profile_name
        user.certificateProfileName = cert_profile_name

        # Generate private key
        private_key, csr = self._generate_csr(
            common_name=subject_dn.cn, bits=bits)

        try:
            # requestData - the PKCS10/CRMF/SPKAC/PUBLICKEY request in base64
            r = self._client.service.certificateRequest(
                user,  # UserDataVOWS
                csr,   # requestData
                CertificateHelper.CERT_REQ_TYPE_PKCS10,  # requestType
                None,  # hardTokenSN
                CertificateHelper.RESPONSETYPE_CERTIFICATE  # responseType
            )

            cert = "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----"
            cert = cert.format(r["data"].decode())
        except zeep.exceptions.Fault as e:
            raise EjbcaClientException(str(e))

        return cert, private_key

    def generate_certificate_pkey_on_server(
        self,
        ca_name: str,
        username: str,
        password: str,
        subject_dn: SubjectDN,
        bits: int = 2048,
        end_entity_profile_name: Optional[str] = None,
        cert_profile_name: Optional[str] = None,
    ) -> bytes:
        """Generate certificate and private key on server

        Args:
            username
            password
            subjectDN
        """
        # Prepea
        if end_entity_profile_name is None:
            end_entity_profile_name = self._default_end_entity_profile_name
        if cert_profile_name is None:
            cert_profile_name = self._default_cert_profile_name

        # Type
        userDataVOWS = self._client.get_type(
            '{http://ws.protocol.core.ejbca.org/}userDataVOWS')

        user = userDataVOWS()

        user.caName = ca_name
        user.username = username
        user.password = password
        user.clearPwd = False
        user.subjectDN = str(subject_dn)

        user.tokenType = UserDataVOWS.TOKEN_TYPE_P12
        user.keyRecoverable = True
        user.sendNotification = False
        user.status = UserDataVOWS.STATUS_NEW
        user.endEntityProfileName = end_entity_profile_name
        user.certificateProfileName = cert_profile_name

        try:
            self._client.service.editUser(user)

            r = self._client.service.pkcs12Req(
                user.username,
                user.password,
                None,
                str(bits),
                AlgorithmConstants.KEYALGORITHM_RSA
            )

            p12_dump = base64.b64decode(r["keystoreData"])
        except zeep.exceptions.Fault as e:
            raise EjbcaClientException(str(e))

        pkey, cert = self._p12_extract_pkey_cert(p12_dump, password)
        return cert, pkey

    def get_latest_crl(self, ca_name: str) -> str:
        """ Return CRL in PEM format """
        try:
            r = self._client.service.getLatestCRL(ca_name, False)
        except zeep.exceptions.Fault as e:
            raise EjbcaClientException(str(e))
        return self._crl_convert_der2pem(r)

    def get_latest_ca_chain(self, ca_name: str) -> str:
        """ Retrun CA Chanin in PEM """
        result = []
        try:
            r = self._client.service.getLastCAChain(ca_name)
        except zeep.exceptions.Fault as e:
            raise EjbcaClientException(str(e))
        for item in r:
            result.append(self._cert_data_to_pem(item))
        return "\n\n".join(result)

    def get_certificate_by_sn(self, sn: str, issuer: str) -> str:
        """Return certificate in PEM by him serial number in hex"""
        try:
            r = self._client.service.getCertificate(sn, issuer)
        except zeep.exceptions.Fault as e:
            raise EjbcaClientException(str(e))
        return self._cert_data_to_pem(r)

    def revoke_certificate_by_sn(self, sn: str, issuer: str):
        """Revoke certificate by him serial number in hex"""
        try:
            self._client.service.revokeCert(issuer, sn, 0)
        except zeep.exceptions.Fault as e:
            raise EjbcaClientException(str(e))

    def restore_certificate_and_private_key_by_sn(
        self,
        sn: str,
        issuer: str,
        username: str,
        password: str
    ) -> Tuple[str, str]:
        """Restore certificate,
        for this in end_entity_profile options recoverable must be enabled

        Args:
            sn - Serial Number Hex
            issuer - Issuer DN

        Return
            Certificate in PEM, Private key in PEM
        """
        try:
            # Marked the certificate as recover
            self._client.service.keyRecover(username, sn, issuer)

            # Set new password and get certificate and pkey in p12 format
            r = self._client.service.keyRecoverEnroll(
                username, sn, issuer, password, None
            )
            result = base64.b64decode(r["keystoreData"])
        except zeep.exceptions.Fault as e:
            raise EjbcaClientException(str(e))
        pkey, cert = self._p12_extract_pkey_cert(result, password)
        return cert, pkey

    def _generate_csr(
        self,
        common_name: str,
        bits: int = 2048,
        country: Optional[str] = None,
        city: Optional[str] = None,
        organization: Optional[str] = None,
        organizational_unit: Optional[str] = None,
        email_address: Optional[str] = None,
    ) -> Tuple[bytes, bytes]:
        """Generate private and Certificate Signing Request (CSR) (PKCS10)

        Args:
            common_name
            bits
            country
            city
            organization
            organizational_unit
            email_address

        Return:
            private key in PEM, CSR in PEM
        """
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits
        )

        # Create CSR
        attributes = []
        if country:
            attributes.append(
                x509.NameAttribute(NameOID.COUNTRY_NAME, country))
        if city:
            attributes.append(
                x509.NameAttribute(NameOID.LOCALITY_NAME, city))
        if organization:
            attributes.append(
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
        if organizational_unit:
            attributes.append(
                x509.NameAttribute(
                    NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit)
            )
        if email_address:
            attributes.append(
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, email_address))
        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ] + attributes)
        )

        csr = csr_builder.sign(private_key, hashes.SHA256())

        # Convert to pem
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)

        return private_key_pem.decode(), csr_pem.decode()

    def _p12_extract_pkey_cert(
        self, data: bytes, password: Optional[str] = None
    ) -> Tuple[str, str]:
        """Extract from p12 private key and certificate

        Args:
            data - format pkcs12 (*.p12)
            password - <PASSWORD>

        Return
            Private key in PEM, Certificate in PEM
        """
        if password is not None:
            password = password.encode()
        private_key, certificate, _ = pkcs12.load_key_and_certificates(
            data, password)
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        certificate_pem = certificate.public_bytes(
            encoding=serialization.Encoding.PEM)
        return private_key_pem.decode(), certificate_pem.decode()

    def _crl_convert_der2pem(self, data_crl: bytes) -> str:
        """Convert CRL from DER to PEM format"""
        crl = x509.load_der_x509_crl(data_crl)
        crl_pem = crl.public_bytes(serialization.Encoding.PEM)
        return crl_pem.decode()

    def _cert_data_to_pem(self, cert_data: "certificate") -> str:
        """Extract from certificate object only certificate"""
        cert = "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----"
        return cert.format(cert_data.certificateData.decode())
