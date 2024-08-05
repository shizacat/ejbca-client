import unittest
from unittest.mock import MagicMock

import zeep.exceptions

from ejbca_client.client import EjbcaClient
from ejbca_client.exception import EjbcaClientException


class TestMain(unittest.TestCase):

    def setUp(self):
        self.obj = EjbcaClient(
            'https://localhost:8443/ejbca',
            wsdl_path="tests/data/ejbca.6.wsdl.xml",
        )

    def test__p12_extract_pkey_cert(self):
        with open('tests/data/temp.p12', 'rb') as f:
            data = f.read()
        pkey, cert = self.obj._p12_extract_pkey_cert(data, "check")
        self.assertIsInstance(pkey, str)
        self.assertIsInstance(cert, str)

    def test__generate_csr(self):
        pkey, csr = self.obj._generate_csr(
            common_name="check",
            bits=2048,
            country="US",
            city="New York",
            organization="Test",
            organizational_unit="TestOU",
            email_address="<EMAIL>",
        )
        self.assertIsInstance(pkey, str)
        self.assertIsInstance(csr, str)

    def test__crl_convert_der2pem(self):
        with open("tests/data/crl.der", "rb") as f:
            data = f.read()
        r = self.obj._crl_convert_der2pem(data)
        self.assertIsInstance(r, str)

    def test_get_latest_crl_01_error(self):
        """
        Test raise zeep.exceptions.Error
        """
        self.obj._client = MagicMock()
        self.obj._client.service = MagicMock()
        self.obj._client.service.getLatestCRL = MagicMock(
            side_effect=zeep.exceptions.Error)

        with self.assertRaises(EjbcaClientException):
            self.obj.get_latest_crl("test")
