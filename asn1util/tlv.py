from enum import IntEnum
from typing import BinaryIO, Union
import logging
from io import BytesIO

logger = logging.getLogger(__name__)

class ASN1EncodingException(Exception):
    def __init__(self, message):
        super().__init__(message)


class InvalidTLV(Exception):
    def __init__(self, message):
        super().__init__(message)


class UnsupportedValueException(InvalidTLV):
    def __init__(self, message=None, value=None):
        if message:
            super().__init__(message)
        else:
            super().__init__(f"类型 {type(self)}不支持值{value}/ Value {value} is not supported by type {type(self)}")


class ValueEncodingException(InvalidTLV):
    def __init__(self, message):
        super().__init__(message)


class TagClass(IntEnum):
    """
    标签类型（tag class）：X.690 8.1.2.2 规定，标签数据的首字节的b8、b7比特标记标签类型
    00：通用
    01：应用
    02：上下文有关
    03：私有
    参见 ISO/IEC 7816-6（GB/T 16449.6）
    """
    UNIVERSAL = 0x00
    APPLICATION = 0x40
    CONTEXT_SPECIFIC = 0x80
    PRIVATE = 0xC0


class TagPC(IntEnum):
    """
    标签结构（tag rule）：X.690 8.1.2.2 规定，标签数据的首字节的b6比特标记标签结构
    0：基本型
    1：构造型
    """
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
    TeletexString = 0x14  # T61String
    VideotexString = 0x15
    IA5String = 0x16
    UTCTime = 0x17
    GeneralizedTime = 0x18
    GraphicString = 0x19
    VisibleString = 0x1a  # ISO646String
    GeneralString = 0x1b
    UniversalString = 0x1c  # UTF8String
    BMPString = 0x1e
    Date = 0x1f
    TimeOfDay = 0x20
    DateTime = 0x21
    Duration = 0x22


"""
字符串类型
"""
RESTRICTED_STRING_TAGS = (
    TagNumber.UTF8String, TagNumber.NumericString, TagNumber.PrintableString, TagNumber.TeletexString,
    TagNumber.VideotexString, TagNumber.IA5String, TagNumber.GraphicString, TagNumber.VisibleString,
    TagNumber.GeneralString, TagNumber.UniversalString, TagNumber.BMPString
)


TagNumber.values = set(item.value for item in TagNumber)
TagNumber.primitive_set = {
    TagNumber.EndOfContent, TagNumber.Boolean, TagNumber.Integer, TagNumber.BitString,
    TagNumber.OctetString, TagNumber.Null, TagNumber.ObjectIdentifier,
    TagNumber.ObjectDescriptor, TagNumber.Real, TagNumber.Enumerated, TagNumber.UTF8String,
    TagNumber.RelativeOID, TagNumber.Time, TagNumber.NumericString, TagNumber.PrintableString,
    TagNumber.TeletexString, TagNumber.IA5String, TagNumber.UTCTime, TagNumber.GeneralizedTime,
    TagNumber.UniversalString, TagNumber.Date, TagNumber.TimeOfDay, TagNumber.DateTime,
    TagNumber.Duration}
TagNumber.constructed_set = {
    TagNumber.BitString, TagNumber.OctetString, TagNumber.ObjectDescriptor,
    TagNumber.UTF8String, TagNumber.Sequence, TagNumber.Set, TagNumber.NumericString,
    TagNumber.PrintableString, TagNumber.TeletexString, TagNumber.IA5String, TagNumber.UTCTime,
    TagNumber.GeneralizedTime, TagNumber.UniversalString}


class Tag:
    """
    Tag Class
    X.690 8.1.2
    """
    def __init__(self, octets: bytes, der: bool = False):
        assert isinstance(octets, bytes), 'Tag octets should be bytes'
        self._octets = octets

        tag_len = len(self._octets)
        initial = self._octets[0]
        self._cls = TagClass(initial & 0xC0)
        self._pc = TagPC(initial & 0x20)

        #  X.690 8.1.2.3
        if tag_len == 1 and 0 <= (self._octets[0] & 0x1F) < 0x1F:
            self._number = initial & 0x1f
        #  X.690 8.1.2.4
        else:  # 当Tag Number为长编号（>30）时，后续字节首位为1，直至首位为0的字节
            assert tag_len > 1, 'High tag number without following octets.'
            self._number = 0 #initial & 0x1f
            for ind, octet in enumerate(self._octets[1:], 1):
                if ind == tag_len - 1:
                    assert octet & 0x80 == 0, 'High tag number octets should end with b8 = 0.'
                else:
                    assert octet & 0x80 == 1, 'High tag number octets should be with b8 = 0 unless the last one.'
                if ind == 1:
                    assert octet & 0x7f != 0, 'High tag number first octet should not be with b7-b1 all zeros.'

                self._number <<= 7
                self._number += octet & 0x3f
            if der:
                assert self._number >= 0x1F, f'High tag number less than 31. {bytes(self._octets).hex()} {self._number}'

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
    def number(self) -> int:
        return self._number

    @property
    def octets(self) -> bytes:
        return self._octets

    def __len__(self) -> int:
        return len(self._octets)

    def __repr__(self):
        return f'{self._octets.hex().upper()}'

    TAG_CLASS_ABBR = {
        TagClass.UNIVERSAL: 'U',
        TagClass.APPLICATION: 'A',
        TagClass.CONTEXT_SPECIFIC: 'C',
        TagClass.PRIVATE: 'P'
    }

    def __str__(self):
        tc = Tag.TAG_CLASS_ABBR[self.cls]
        tt = 'P' if self.is_primitive else 'C'
        tn = TagNumber(self.number).name if (self.cls == TagClass.UNIVERSAL and self.number in TagNumber.values) else ''
        return f'{tc}{tt}|{tn}({repr(self)})'

    @staticmethod
    def build(cls: TagClass, pc: TagPC, number: int) -> 'Tag':
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
    def decode(data: Union[bytes, bytearray, BinaryIO]):
        if isinstance(data, bytes) or isinstance(data, bytearray):
            data = BytesIO(data)
        buffer = data.read(1)
        if len(buffer) == 0:  # EOF of data
            return None

        if buffer[0] & 0x1f != 0x1f:  # Low tag number form
            return Tag(buffer)

        octets = bytearray()
        octets.append(buffer[0])
        while buffer := data.read(1):
            octets.extend(buffer)
            if buffer[0] & 0x80 == 0:
                break

        return Tag(bytes(octets))


class Length:
    INDEFINITE = b'\x80'

    def __init__(self, octets: bytes, der: bool = False):
        self._octets = octets

        assert self._octets
        seg_len = len(self._octets)
        initial = self._octets[0]

        if initial == Length.INDEFINITE[0]:  # 不确定长度格式（X.690 8.1.3.6）
            if der:
                raise ASN1EncodingException(f"DER格式不支持不定长格式/Indefinite length is not supported in DER.")
            self._value = None
        elif initial & 0x80 == 0:  # 短长度格式（X.690 8.1.3.4）
            assert seg_len == 1
            self._value = initial & 0x7f
            assert self._value < 127
        else:
            assert seg_len == (initial & 0x7f) + 1 and initial != 0xff
            self._value = int.from_bytes(self._octets[1:], byteorder='big', signed=False)

    @staticmethod
    def build(length_value: int) -> 'Length':
        if length_value is None:
            return Length(Length.INDEFINITE)
        assert length_value >= 0, 'Length value is less than 0'

        if length_value < 127:
            return Length(length_value.to_bytes(1, byteorder='big', signed=False))
        else:
            length_octets = (length_value.bit_length() + 7) // 8
            if length_octets > 127:
                raise InvalidTLV("Length value is more than 127 bytes.")

            res = bytearray((length_octets | 0x80).to_bytes(1, byteorder='big', signed=False))
            res.extend(length_value.to_bytes(length_octets, byteorder='big', signed=False))
            return Length(bytes(res))

    @property
    def is_definite(self):
        return self._value is not None

    @property
    def value(self):
        return self._value

    @property
    def octets(self):
        return self._octets

    def __len__(self) -> int:
        return len(self._octets)

    @staticmethod
    def decode(data: BinaryIO):
        buffer = data.read(1)
        if len(buffer) == 0:
            raise InvalidTLV("剩余字节不足，长度缺失/ Insufficent octects, missing length.")
        initial = buffer[0]

        if initial == 0x80:  # Indefinite length
            return Length(buffer)
        elif initial & 0x80 == 0:  # Short form length
            return Length(buffer)
        else:  # Long form length
            buffer = bytearray()
            buffer.append(initial)
            buffer.extend(data.read(initial & 0x7f))
            if len(buffer) < (initial & 0x7f) + 1:
                raise InvalidTLV(
                    f"剩余字节不足，长度缺失/ Insufficent octects, incomplete length. (0x{buffer.hex()})")
            return Length(buffer)

    def __repr__(self):
        if self.is_definite:
            return f"{self._value}"
        else:
            return "INDEFINITE"


class Value:
    def __init__(self, octets: bytes):
        assert isinstance(octets, bytes)
        self._octets = octets
        self._value = None

    def __getitem__(self, index):
        return self._octets[index]

    def __len__(self):
        return len(self._octets)

    def __repr__(self):
        return self._octets.hex(' ')

    @property
    def value(self):
        return self._value

    def __str__(self):
        return str(self._value)

