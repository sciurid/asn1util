from abc import abstractmethod

from .exceptions import InvalidEncoding, DERIncompatible, UnsupportedValue
from .tlv import Tag, Length
from .util import signed_int_to_bytes
from typing import BinaryIO, Union

# X.680 Table 1 (P14)
TAG_EOC = Tag(b'\x00')
TAG_Boolean = Tag(b'\x01')
TAG_Integer = Tag(b'\x02')
TAG_BitString = Tag(b'\x03')
TAG_OctetString = Tag(b'\x04')
TAG_Null = Tag(b'\x05')
TAG_ObjectIdentifier = Tag(b'\x06')
TAG_ObjectDescriptor = Tag(b'\x07')
TAG_External_InstanceOf = Tag(b'\x08')
TAG_Real = Tag(b'\x09')
TAG_Enumerated = Tag(b'\x0A')
TAB_EmbeddedPdv = Tag(b'\x0B')
TAG_UTF8String = Tag(b'\x0C')
TAG_RelativeObjectIdentifier = Tag(b'\x0D')
TAG_Time = Tag(b'\x0E')
TAG_Reserved = Tag(b'\x0F')
TAG_Sequence = Tag(b'\x30')
TAG_Set = Tag(b'\x31')
TAG_NumericString = Tag(b'\x12')
TAG_PrintableString = Tag(b'\x13')
TAG_TeletexString = Tag(b'\x14')
TAG_VideotexString = Tag(b'\x15')
TAG_IA5String = Tag(b'\x16')
TAG_UTCTime = Tag(b'\x17')
TAG_GeneralizedTime = Tag(b'\x18')
TAG_GraphicString = Tag(b'\x19')
TAG_VisibleString = Tag(b'\x1a')  # ISO646String
TAG_GeneralString = Tag(b'\x1b')
TAG_UniversalString = Tag(b'\x1c')  # UTF8String
TAG_BMPString = Tag(b'\x1e')
# TAG_Date = Tag(b'\x1f')
# TAG_TimeOfDay = Tag(b'\x20')
# TAG_DateTime = Tag(b'\x21')
# TAG_Duration = Tag(b'\x22')


class ASN1DataType:
    """表示各种数据格式的基类
    """
    def __init__(self, length: Length = None, value=None, value_octets: bytes = None, der: bool = False):
        """通过标签（Tag）、长度（Length）、数值（Value）构建成的ASN.1数据对象

        :param tag: ASN.1数据对象的标签
        :param tag: ASN.1数据对象的长度
        :param value: ASN.1数据对象表示的的数值
        :param value_octets: ASN.1数据对象数值的字节串表示
        :param der: ASN.1数据对象是否符合DER规范

        构建过程中将检查参数一致性。
        """
        self._der = der
        self._length = length

        if value is None:
            if value_octets is None:  # 数值和字节串均为None
                raise ValueError("数值value或数值字节串value_octets均为None")
            else:   # 仅有数值字节串，则保留字节串并计算数值，常用于解码情况
                self._value_octets = value_octets
                self._value = self.decode_value(value_octets, der)
                if length is None:
                    self._length = Length.build(len(value_octets))
                elif len(value_octets) != length.value:
                    raise ValueError("数值字节串value_octets长度与length不一致")
        else:
            self._value = value
            if value_octets is None:  # 仅有数值，则通过数值计算字节串（通常应当遵循DER编码规则），常用于编码情况
                self._value_octets = self.encode_value(value)
                if length is None:
                    self._length = Length.build(len(self._value_octets))
                else:
                    if len(self._value_octets) != length.value:
                        raise ValueError("数值value编码出的字节串长度与length不一致")
            else:   # 两者都有时，则保留字节串并以此计算数值（考虑到非DER等编码不唯一情况），并与数值核对
                self._value_octets = value_octets
                decoded = self.decode_value(self._value_octets, der)
                if value != decoded:
                    raise ValueError("数值value或数值字节串value_octets不一致")

    @classmethod
    def tag(cls) -> Tag:
        """返回数据对象标签"""
        raise NotImplementedError()

    @classmethod
    def tag_name(cls) -> str:
        """返回数据对象名称"""
        raise NotImplementedError()

    @classmethod
    def decode_value(cls, octets: bytes, der: bool):
        """将数值字节串转化为数值，由具体类型实现

        :param octets: 数值字节串
        :param der: 是否遵循DER编码规则
        :return: 对应的数值
        """
        raise NotImplementedError()

    @classmethod
    def encode_value(cls, value) -> bytes:
        """将数值转化为数值字节串，由具体类型实现

        :param value: 数值
        :return: 数值字节串
        """
        raise NotImplementedError()

    @property
    def value(self):
        return self._value

    @property
    def value_octets(self):
        return self._value_octets

    @property
    def octets(self):
        buffer = bytearray(self.tag().octets)
        buffer.extend(self._length.octets)
        buffer.extend(self._value_octets)
        return bytes(buffer)

    def __eq__(self, other):
        return (self.tag() == other.tag() and self._length == other._length
                and self.value == other.value)

    def __repr__(self):
        return ('[ASN.1 {}]{} ({} {} {})'
                .format(self.tag_name(), self.value,
                        self.tag().octets.hex().upper(), self._length.octets.hex().upper(),
                        self._value_octets.hex().upper()))

class ASN1EndOfContent(ASN1DataType):

    """X.690 8.1.5 EOC"""
    def __init__(self, der: bool = False):
        super().__init__(Length.build(0), None, b'')
        if der:
            raise DERIncompatible('DER编码中不出现不确定长度和EOC数据对象')

    @classmethod
    def tag(cls) -> Tag:
        return TAG_EOC

    @classmethod
    def tag_name(cls) -> str:
        return 'End-of-content'

    @classmethod
    def decode_value(cls, octets: bytes, der: bool):
        if octets != b'':
            raise InvalidEncoding('EOC值字节必须为空', octets)
        return None

    @classmethod
    def encode_value(cls, value) -> bytes:
        if value is not None:
            raise UnsupportedValue('EOC值必须为None', value)
        return b''


class ASN1Boolean(ASN1DataType):
    """X.690 8.2 Boolean"""
    def __init__(self, length: Length = None, value: bool = None, value_octets: bytes = None, der: bool = False):
        super().__init__(length, value, value_octets, der)

    @classmethod
    def tag(cls) -> Tag:
        return TAG_Boolean

    @classmethod
    def tag_name(cls) -> str:
        return 'Boolean'

    @classmethod
    def decode_value(cls, octets: bytes, der: bool) -> bool:
        if octets == b'\x00':
            return False
        elif octets != b'\xff' and der:
            raise DERIncompatible('Boolean类型DER编码只能为0x00和0xff', octets)
        else:
            return True

    @classmethod
    def encode_value(cls, value: bool) -> bytes:
        return b'\xff' if value else b'\x00'


class ASN1Integer(ASN1DataType):
    """X.690 8.3 Integer"""
    def __init__(self, length: Length = None, value: int = None, value_octets: bytes = None, der: bool = False):
        super().__init__(length, value, value_octets, der)

    @classmethod
    def tag(cls) -> Tag:
        return TAG_Integer

    @classmethod
    def tag_name(cls) -> str:
        return 'Integer'

    @classmethod
    def decode_value(cls, octets: bytes, der: bool) -> int:

        if len(octets) > 1 \
            and ((octets[0] == 0x00 and octets[1] & 0x80 == 0) or (octets[0] == 0xff and octets[1] & 0x80 == 1)):
            raise InvalidEncoding("Integer数值编码首字节不能全0或全1")
        return int.from_bytes(octets, byteorder='big', signed=True)

    @classmethod
    def encode_value(cls, value: int) -> bytes:
        return signed_int_to_bytes(value)

class ASN1Enumerated(ASN1Integer):
    """X.690 8.4 Enumerated"""
    def __init__(self, length: Length = None, value: int = None, value_octets: bytes = None, der: bool = False):
        super().__init__(length, value, value_octets, der)

    @classmethod
    def tag(cls) -> Tag:
        return TAG_Enumerated

    @classmethod
    def tag_name(cls) -> str:
        return 'Enumerated'


class ASN1Real(ASN1DataType):

    def __init__(self, length: Length = None, value: float = None, value_octets: bytes = None, der: bool = False):
        super().__init__(length, value, value_octets, der)


DATA_TYPES = {
    b'\x00': ASN1EndOfContent,
    b'\x01': ASN1Boolean,
    b'\x02': ASN1Integer,
}
