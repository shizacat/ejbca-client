class EjbcaClientException(Exception):
    """Base Exception"""


class ConnectionError(EjbcaClientException):
    """Connection error"""


class ZeepError(EjbcaClientException):
    """Zeep error"""
