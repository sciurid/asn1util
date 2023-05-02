from .tlv import UnsupportedValueException
from typing import Iterable, Union
import re


class InvalidObjectIdentifier(UnsupportedValueException):
    def __init__(self, message):
        self.message = message


class ObjectIdentifier:
    def __init__(self, components: Iterable[int]):
        self._components = tuple(value for value in components)
        self._validate()

    def _validate(self):
        if len(self._components) < 2:
            raise InvalidObjectIdentifier('ObjectIdentifier should consist of at least 2 components.')
        if self._components[0] in (0, 1):
            if self._components[1] < 0 or self._components[1] > 39:
                raise InvalidObjectIdentifier(
                    'ObjectIdentifier value 2 should be between 0 to 39 when value 1 is 0 or 1.')
        elif self._components[0] == 2:
            return
        else:
            raise InvalidObjectIdentifier('ObjectIdentifier value 1 should be 0, 1 or 2.')

    @property
    def components(self):
        return self._components

    def __repr__(self):
        return '.'.join([str(i) for i in self._components])

    def to_octets(self) -> bytes:
        data = [self.components[0] * 40 + self.components[1]]
        data.extend(self.components[2:])
        data.reverse()
        octets = bytearray()
        for comp in data:
            octets.append(comp & 0x7f)
            comp >>= 7
            while comp > 0:
                octets.append(comp & 0x7f | 0x80)
                comp >>= 7
        octets.reverse()
        return octets

    @staticmethod
    def encode(value: Union['ObjectIdentifier', str, Iterable[int]]):
        if isinstance(value, ObjectIdentifier):
            return value.to_octets()
        elif isinstance(value, str):
            return ObjectIdentifier.decode_string(value).to_octets()
        elif isinstance(value, Iterable):
            return ObjectIdentifier(value).to_octets()
        else:
            raise InvalidObjectIdentifier('OID value should be a string or a sequence of integers.')

    OID_STRING_PATTERN: re.Pattern = re.compile(r'^[012](\.[0-9]+)+$')

    @staticmethod
    def decode_string(value: str):
        mo = ObjectIdentifier.OID_STRING_PATTERN.match(value)
        if mo is None:
            raise InvalidObjectIdentifier(f'"{value}" is not a valid ObjectIdentifier.')
        return ObjectIdentifier([int(item) for item in value.split('.')])

    @staticmethod
    def decode(data: bytes):
        components = []
        comp = 0
        for octet in data:
            comp = (comp << 7) | (octet & 0x7f)
            if octet & 0x80 == 0:
                components.append(comp)
                comp = 0
        if data[-1] & 0x80 > 0:
            raise InvalidObjectIdentifier(f'Last octet of encoded object identifier with b8 = 1.')

        combined = components[0]

        if combined < 80:
            components[0] -= (combined // 40) * 40
            components.insert(0, combined // 40)
        else:
            components[0] -= 80
            components.insert(0, 2)

        return ObjectIdentifier(components)
