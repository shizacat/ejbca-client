import unittest

from ejbca_client.client import EjbcaClient


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
