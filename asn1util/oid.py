from .tlv import UnsupportedValueException
from typing import Iterable, Union
from .oid_info import OIDQueryService
import re

class InvalidObjectIdentifier(UnsupportedValueException):
    def __init__(self, message):
        self.message = message


class ObjectIdentifier:
    def __init__(self, octets: bytes):
        sub_ids = []  # Subidentifiers (X.680 8.19.2)
        sn = 0  # Subidentifier
        for b in octets:
            assert (sn != 0) or (b != 0x80)  # Subidenfier的首字节不能是0x80
            sn = (sn << 7) | (b & 0x7f)
            if b & 0x80 == 0:
                sub_ids.append(sn)
                sn = 0
        assert octets[-1] & 0x80 == 0  # 尾字节的b8 = 0
        component_1 = sub_ids[0] // 40 if sub_ids[0] < 80 else 2
        component_2 = sub_ids[0] - component_1 * 40

        self._components = (component_1, component_2, *sub_ids[1:])

    @property
    def components(self):
        return self._components

    def __repr__(self):
        return '.'.join([str(i) for i in self._components])

    def __str__(self):
        value = repr(self)
        name = OIDQueryService().query(value)[1]
        return f'{value} ({name})'

    OID_STRING_PATTERN: re.Pattern = re.compile(r'^[012](\.[0-9]+)+$')

    @staticmethod
    def encode(components: Union[str, list, tuple]):
        if instanceof(components, str):
            mo = ObjectIdentifier.OID_STRING_PATTERN.match(value)
            if mo is None:
                raise InvalidObjectIdentifier(f'"{components}" is not a valid ObjectIdentifier.')
            ObjectIdentifier.encode((int(item) for item in components.split('.')))

        assert ((0 <= components[1] < 40) and (0 <= components[0] < 2)) \
               or ((components[0] == 2) and (0 <= components[1]))

        octets = bytearray()
        for comp in reversed (components[0] * 40 + components[1], *components[2:]):
            octets.append(comp & 0x7f)
            comp >>= 7
            while comp > 0:
                octets.append(comp & 0x7f | 0x80)
                comp >>= 7
        octets.reverse()

    @staticmethod
    def decode(octets: bytes):
        return ObjectIdentifier(octets)
