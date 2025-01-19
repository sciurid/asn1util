class ASN1Exception(Exception):
    def __init__(self, message):
        super().__init__(message)


class InvalidEncoding(ASN1Exception):
    def __init__(self, message, data=None):
        super().__init__(message)
        self._data = data

    @property
    def data(self):
        return self._data


class DERIncompatible(InvalidEncoding):
    def __init__(self, message, data=None):
        super().__init__(message, data)


class UnsupportedValue(ASN1Exception):
    def __init__(self, message, data=None):
        super().__init__(message)
        self._data = data

    @property
    def data(self):
        return self._data
