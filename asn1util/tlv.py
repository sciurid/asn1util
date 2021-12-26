from enum import IntEnum
from typing import BinaryIO, Union
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class InvalidTLV(Exception):
    def __init__(self, message):
        self.message = message


class InvalidValue(InvalidTLV):
    def __init__(self, message):
        self.message = message


class TagClass(IntEnum):
    UNIVERSAL = 0x00
    APPLICATION = 0x40
    CONTEXT_SPECIFIC = 0x80
    PRIVATE = 0xC0


class TagPC(IntEnum):
    PRIMITIVE = 0x00
    CONSTRUCTED = 0x20


class TagNumber(IntEnum):
    EndOfContent = 0x00
    Boolean = 0x01
    Integer = 0x02
    BitString = 0x03
    OctetString = 0x04
    Null = 0x05
    ObjectIdentifier = 0x06
    ObjectDescriptor = 0x07
    External = 0x08
    Real = 0x09
    Enumerated = 0x0a
    UTF8String = 0x0c
    RelativeOID = 0x0d
    Time = 0x0e
    Sequence = 0x10
    Set = 0x11
    NumericString = 0x12
    PrintableString = 0x13
    T61String = 0x14
    IA5String = 0x16
    UTCTime = 0x17
    GeneralizedTime = 0x18
    UniversalString = 0x1c
    BMPString = 0x1e
    Date = 0x1f
    TimeOfDay = 0x20
    DateTime = 0x21
    Duration = 0x22


TagNumber.values = set(item.value for item in TagNumber)
TagNumber.primitive_set = {
    TagNumber.EndOfContent, TagNumber.Boolean, TagNumber.Integer, TagNumber.BitString,
    TagNumber.OctetString, TagNumber.Null, TagNumber.ObjectIdentifier,
    TagNumber.ObjectDescriptor, TagNumber.Real, TagNumber.Enumerated, TagNumber.UTF8String,
    TagNumber.RelativeOID, TagNumber.Time, TagNumber.NumericString, TagNumber.PrintableString,
    TagNumber.T61String, TagNumber.IA5String, TagNumber.UTCTime, TagNumber.GeneralizedTime,
    TagNumber.UniversalString, TagNumber.Date, TagNumber.TimeOfDay, TagNumber.DateTime,
    TagNumber.Duration}
TagNumber.constructed_set = {
    TagNumber.BitString, TagNumber.OctetString, TagNumber.ObjectDescriptor,
    TagNumber.UTF8String, TagNumber.Sequence, TagNumber.Set, TagNumber.NumericString,
    TagNumber.PrintableString, TagNumber.T61String, TagNumber.IA5String, TagNumber.UTCTime,
    TagNumber.GeneralizedTime, TagNumber.UniversalString}


class Tag:
    def __init__(self, octets: Union[bytes, bytearray]):
        assert octets, 'Tag octets should not be None or empty.'
        self._octets = bytes(octets)
        self._eval()
        self._validate()

    def _eval(self):
        initial = self._octets[0]
        self._cls = TagClass(initial & 0xC0)
        self._pc = TagPC(initial & 0x20)
        if self.low_tag_number:
            self._number = initial & 0x1f
        else:
            number = 0
            for octet in self._octets[1:]:
                number = (number << 7) + (octet & 0x3f)
            else:
                assert octet & 0x80 == 0, 'High tag number octets do not end with b8 = 0.'
            self._number = number

    def _validate(self):
        if self._cls != TagClass.UNIVERSAL:
            return
        if self._number not in TagNumber.values:
            return
        tn = TagNumber(self._number)
        if self.is_primitive:
            if tn in TagNumber.primitive_set:
                return
        else:
            if tn in TagNumber.constructed_set:
                return
        raise InvalidTLV(f"Universal class type {tn.name} should not be {self.pc.name}.")

    @property
    def cls(self) -> TagClass:
        return TagClass(self._octets[0] & 0xC0)

    @property
    def pc(self) -> TagPC:
        return TagPC(self._octets[0] & 0x20)

    @property
    def is_primitive(self) -> bool:
        return self.pc == TagPC.PRIMITIVE

    @property
    def low_tag_number(self) -> bool:
        return len(self._octets) == 1 and 0 <= (self._octets[0] & 0x1F) < 0x1F

    @property
    def number(self) -> int:
        return self._number

    @property
    def octets(self) -> bytes:
        return self._octets

    @property
    def value(self):
        return self.octets.hex().upper()

    @staticmethod
    def encode(cls: TagClass, pc: TagPC, number: int):
        tag_initial = cls | pc
        if number < 0x1f:
            tag_initial |= number
            return Tag(bytes([tag_initial]))
        else:
            res = bytearray()
            while number > 0:
                res.append((number & 0x7f) | 0x80)
                number >>= 7
            res[0] &= 0x7f
            res.append(tag_initial | 0x1f)
            res.reverse()
            return Tag(bytes(res))

    @staticmethod
    def decode(data: BinaryIO):
        buffer = data.read(1)
        if len(buffer) == 0:  # EOF of data
            return None

        octets = bytearray()
        tag_initial = buffer[0]
        octets.append(tag_initial)

        short_number = tag_initial & 0x1f
        if short_number == 0x1f:  # High tag number form
            while buffer := data.read(1):
                octet = buffer[0]
                octets.append(octet)
                if octet & 0x80 == 0:
                    break
            else:
                raise InvalidTLV("High tag number bytes not end. (No following byte or b8 == 1 for the last byte)")
            if len(octets) == 1:
                raise InvalidTLV("High tag number with no bytes following.")
            elif octets[1] & 0x7f == 0:
                raise InvalidTLV("High tag number with b7 to b1 being 0 in the first following octet.")
            return Tag(octets)
        else:
            return Tag(bytes([tag_initial]))

    TAG_CLASS_ABBR = {
        TagClass.UNIVERSAL: 'UNIV',
        TagClass.APPLICATION: 'APP',
        TagClass.CONTEXT_SPECIFIC: 'CTXT-SPEC',
        TagClass.PRIVATE: 'PRIV'
    }

    def __repr__(self):
        if self.cls == TagClass.UNIVERSAL:
            tn = TagNumber(self.number) if self.number in TagNumber.values else None
            if tn is not None:
                return f'{self.value} ({tn.name})'
            else:
                return f'{self.value} (UNKNOWN)'
        else:
            return f'{self.value} ({Tag.TAG_CLASS_ABBR[self.cls]})'


class Length:
    INDEFINITE = b'\x80'

    def __init__(self, length_value: Union[int, None]):
        self._length_value = length_value
        self._data = Length.encode(length_value)

    @staticmethod
    def encode(length_value: int) -> bytes:
        if length_value is None:
            return Length.INDEFINITE
        if length_value < 0:
            raise InvalidTLV("Length value is less than 0.")
        if length_value < 128:
            return bytes([length_value])
        else:
            length_octets = (length_value.bit_length() + 7) // 8
            if length_octets > 127:
                raise InvalidTLV("Length value is more than 127 bytes.")

            res = bytearray([length_octets | 0x80])
            res.extend(length_value.to_bytes(length_octets, byteorder='big'))
            return bytes(res)

    @property
    def is_definite(self):
        return self._data != Length.INDEFINITE

    @property
    def value(self):
        return self._length_value

    @property
    def octets(self):
        return self._data

    @staticmethod
    def decode(data: BinaryIO):
        buffer = data.read(1)
        if len(buffer) == 0:
            raise InvalidTLV("Length octet is missing.")
        length_initial = buffer[0]

        if length_initial == 0x80:  # Indefinite length
            length = Length(None)
        elif length_initial & 0x80 == 0:  # Short form length
            length = Length(length_initial)
        else:  # Long form length
            length_rest = length_initial & 0x7f
            length_octets = data.read(length_rest)
            if len(length_octets) < length_rest:
                raise InvalidTLV(
                    f"Long form length with not enough additional length octets. (0x{length_octets.hex()})")
            length = Length(int.from_bytes(length_octets, byteorder='big'))
        return length

    def __repr__(self):
        if self.is_definite:
            return f"[L]{self._length_value}"
        else:
            return "[L]INF"
