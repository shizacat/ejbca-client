from unittest import TestCase

from ejbca_client import SubjectDN, cert_pem_extract_serial


cert = """
-----BEGIN CERTIFICATE-----
MIIDoDCCAwmgAwIBAgIGcY4uj4qPMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMM
BkNGVGVzdDAeFw0yMjEwMDYwNzQwMDRaFw0yNDEwMDUwNzQwMDRaMBExDzANBgNV
BAMMBmNoZWNrMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKpc0Qrw
KOAWwe0kcpDD7enTfjqRdrWcgH1PDXpxOM99blZuix4/EkMP+VTIiYHCdfX89c8I
3CJgee5WludcY2btt2FpEHe4RU2QVGlP7Lyu7b38slOxOJFvugAOMwjD1O3Hnljb
bDFS/KmfEN++v65K51pXmmXBC+xXJeUWqfUGZFhaRsD8DIaHOg349UnvMZPZGtbC
981l4eZ4va9mAAiHcguthja+eetkksKVnCLbZ74BuPSz9aWVSrhEEvV6wfsrjUwj
0rODMxlvU3hCUExrLGArArcFSjPFWdlr77x7lpifWrikE/OCrmkg8uKf2840Z49Y
kAtU5BGEC/Yj/jTceMcZO3dvEWZo57TSGE2ST8CebpVjRPwL/nh2hvQ8uqSOusYB
q7iUZFt/ZI8iBGQoGnqLaN1NsifQb9gK2iWHvZ4KzhKtcasKIf1WTwjjRo39KUgF
mAEfkg1OBZgG8zeu2qTHzucWiQljvSMFFZyDWz8cE+S8O9eqBZMGS6CZNMfX5Iir
uO1efWYc0Pr16W3y/JdSAFNuR0DMSpxadMs7fCViCQH+zFDF4U7vAbEUhCeXTrDQ
+kO8ZpLHcAousOSpnjsv4/29JhbA37MpZbP9ZPWfWsOMpuvPiBStw/99ThMezTuC
yJ0kVfKnbNHrovMB2qX04hDCfq9wCdV96YY/AgMBAAGjfzB9MAwGA1UdEwEB/wQC
MAAwHwYDVR0jBBgwFoAUfrFCVbpr1+adenPGVQ30oR9CM/QwHQYDVR0lBBYwFAYI
KwYBBQUHAwIGCCsGAQUFBwMEMB0GA1UdDgQWBBTiqi0DOB64cI+ftzYMtSWN9/Tf
TzAOBgNVHQ8BAf8EBAMCBeAwDQYJKoZIhvcNAQELBQADgYEARwTcoPQuCatFrTRj
yp6F4Uuaf/zdR9ze9TXcLIJ0ycZ1ac6eJVEbjrL933oE57uJI+766lDRuMZJL6B+
6chf2UJ28aXZ0xqBl3WrzVn9qciSlFJjaurDXFLtOvD7YQzBPHEhr485TNv2bllw
1a/x0CpRTG+7n1Ko+58j66pX8P8=
-----END CERTIFICATE-----
"""


class TestMain(TestCase):
    def test_create_subjectDN(self):
        obj = SubjectDN(cn="check")
        self.assertEqual(str(obj), "CN=check")

        obj = SubjectDN(cn="check", o="org")
        self.assertEqual(str(obj), "CN=check, O=org")

    def test_cert_pem_extract_serial(self):
        sn = cert_pem_extract_serial(cert)
        self.assertEqual(sn, "718e2e8f8a8f")
