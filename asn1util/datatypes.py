import struct
from decimal import Decimal

from .real import (SpecialRealValue, to_decimal_encoding, to_binary_encoding,
                   int_to_base2_sne, ieee754_double_to_base2_sne, decimal_to_base2_sne, to_ieee758_double)
from .exceptions import InvalidEncoding, DERIncompatible, UnsupportedValue
from .tlv import Tag, Length
from .util import signed_int_to_bytes

from typing import Union

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

        :param length: ASN.1数据对象的长度
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


    def decode_value(self, octets: bytes, der: bool):
        """将数值字节串转化为数值，由具体类型实现

        :param octets: 数值字节串
        :param der: 是否遵循DER编码规则
        :return: 对应的数值
        """
        raise NotImplementedError()

    def encode_value(self, value) -> bytes:
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

    def decode_value(self, octets: bytes, der: bool):
        if octets != b'':
            raise InvalidEncoding('EOC值字节必须为空', octets)
        return None

    def encode_value(self, value) -> bytes:
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

    def decode_value(self, octets: bytes, der: bool) -> bool:
        if octets == b'\x00':
            return False
        elif octets != b'\xff' and der:
            raise DERIncompatible('Boolean类型DER编码只能为0x00和0xff', octets)
        else:
            return True

    def encode_value(self, value: bool) -> bytes:
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

    def decode_value(self, octets: bytes, der: bool) -> int:

        if len(octets) > 1 \
            and ((octets[0] == 0x00 and octets[1] & 0x80 == 0) or (octets[0] == 0xff and octets[1] & 0x80 == 1)):
            raise InvalidEncoding("Integer数值编码首字节不能全0或全1")
        return int.from_bytes(octets, byteorder='big', signed=True)

    def encode_value(self, value: int) -> bytes:
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
    def __init__(self, length: Length = None, value=None, value_octets: bytes = None, der: bool = False, base: int = 2):
        self._base = base
        super().__init__(length, value, value_octets, der)
        if der and base != 2 and base != 10:
            if der:
                raise DERIncompatible("DER编码实数Real类型仅限底数为2或10")
        elif base not in (2, 8, 16, 10):
            raise ValueError("实数Real类型仅限底数为2或10")

    @classmethod
    def tag(cls) -> Tag:
        return TAG_Real

    @classmethod
    def tag_name(cls) -> str:
        return 'Real'

    def decode_value(self, octets: bytes, der: bool) -> Union[float, Decimal, SpecialRealValue]:
        leading = octets[0]
        if (b8b7 := leading & 0xc0) == 0x00:  # b8b7=0，十进制表示
            # X.690 8.5.8 (P8)
            if (nr := leading & 0x3f) < 4:
                if self._der and nr != 0x03:  # DER且非NR3格式
                    raise DERIncompatible("DER编码的十进制实数只允许ISO 6093 NR3格式")
            else:
                raise InvalidEncoding("无法识别的数字格式0x{:02x}".format(leading))
            return Decimal(octets[1:].decode('ascii'))  # TODO:BER/DER编码检查
        elif b8b7 == 0x40:  # 特殊实数 Special Real Values
            if leading & 0x3f < 0x04:
                return SpecialRealValue(leading)
            else:
                raise InvalidEncoding("特殊实数保留值{}".format(hex(leading)))
        else:  # b8=1，二进制表示
            s: int = 1 if leading & 0x40 == 0 else -1
            f: int = (leading & 0x0c) >> 2

            if (b2b1 := leading & 0x03) == 0x00:
                e: int = int.from_bytes(octets[1:2], byteorder='big')
                n: int = int.from_bytes(octets[2:], byteorder='big')
            elif b2b1 == 0x01:
                e: int = int.from_bytes(octets[1:3], byteorder='big')
                n: int = int.from_bytes(octets[3:], byteorder='big')
            elif b2b1 == 0x02:
                e: int = int.from_bytes(octets[1:4], byteorder='big')
                n: int = int.from_bytes(octets[4:], byteorder='big')
            else:
                el = int.from_bytes(octets[1:2], byteorder='big')
                e: int = int.from_bytes(octets[2:el + 2], byteorder='big')
                n: int = int.from_bytes(octets[el + 2:], byteorder='big')

            if (b6b5 := leading & 0x30) == 0x00:
                base = 2
            elif b6b5 == 0x10:
                base = 8
                e = e * 3 + f
            elif b6b5 == 0x20:
                base = 16
                e = e * 4+ f
            else:
                raise InvalidEncoding("二进制底数保留值{}".format(hex(leading)))
            if base != self._base:
                raise InvalidEncoding("二进制底数不一致{} != {:d}".format(hex(leading), self._base))

            return to_ieee758_double(s, n, e)

    def encode_value(self, value: Union[int, float, Decimal]) -> bytes:
        if srv := SpecialRealValue.check_special_value(value):
            return srv.octets

        if self._base == 10:
            if isinstance(value, float):
                return to_decimal_encoding(Decimal(value))
            else:
                return to_decimal_encoding(value)
        else:
            if isinstance(value, int):
                return to_binary_encoding(*int_to_base2_sne(value))
            elif isinstance(value, float):
                sne = ieee754_double_to_base2_sne(struct.pack('>d', value))
                if isinstance(sne, SpecialRealValue):
                    return bytes((sne, ))
                else:
                    return to_binary_encoding(*sne, base=self._base)
            elif isinstance(value, Decimal):
                sne = decimal_to_base2_sne(value)
                return to_binary_encoding(*sne, base=self._base)
            else:
                raise ValueError("数据{}类型不是int、float或Decimal".format(value))

DATA_TYPES = {
    b'\x00': ASN1EndOfContent,
    b'\x01': ASN1Boolean,
    b'\x02': ASN1Integer,
}
