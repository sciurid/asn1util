import re
from typing import Union, Tuple, Sequence
import struct
from decimal import Decimal
from datetime import datetime, timedelta, timezone

from .real import (SpecialRealValue, to_decimal_encoding, to_binary_encoding,
                   int_to_base2_sne, ieee754_double_to_base2_sne, decimal_to_base2_sne, to_ieee758_double)
from .exceptions import InvalidEncoding, DERIncompatible, UnsupportedValue
from .tlv import Tag, Length
from .util import signed_int_to_bytes

# X.680 Table 1 (P14)
TAG_EOC = Tag(b'\x00')
TAG_Boolean = Tag(b'\x01')
TAG_Integer = Tag(b'\x02')
TAG_BitString = Tag(b'\x03')
TAG_BitString_Constructed = Tag(b'\x23')
TAG_OctetString = Tag(b'\x04')
TAG_OctetString_Constructed = Tag(b'\x24')
TAG_Null = Tag(b'\x05')
TAG_ObjectIdentifier = Tag(b'\x06')
TAG_ObjectDescriptor = Tag(b'\x07')
# TAG_External_InstanceOf = Tag(b'\x08')
TAG_Real = Tag(b'\x09')
TAG_Enumerated = Tag(b'\x0A')
# TAB_EmbeddedPdv = Tag(b'\x0B')
TAG_UTF8String = Tag(b'\x0C')
# TAG_RelativeObjectIdentifier = Tag(b'\x0D')
TAG_Time = Tag(b'\x0E')
# TAG_Reserved = Tag(b'\x0F')
TAG_Sequence = Tag(b'\x30')
TAG_Set = Tag(b'\x31')
TAG_NumericString = Tag(b'\x12')
TAG_PrintableString = Tag(b'\x13')
# TAG_TeletexString = Tag(b'\x14')
# TAG_VideotexString = Tag(b'\x15')
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
    """X.690 8.4 Real"""
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


class ASN1BitString(ASN1DataType):
    def __init__(self, length: Length = None, value: Tuple[bytes, int] = None, value_octets: bytes = None,
                 der: bool = False):
        super().__init__(length, value, value_octets, der)

    @classmethod
    def tag_name(cls) -> str:
        return 'BitString'

    @classmethod
    def tag(cls) -> Tag:
        return TAG_BitString

    def decode_value(self, octets: bytes, der: bool) -> Tuple[bytes, int]:
        if len(octets) == 0:
            raise InvalidEncoding("BitString至少应该有1个字节")
        if len(octets) == 1 and octets[0] != 0x00:  # X.690 8.6.2.3
            raise InvalidEncoding("BitString为空时首字节应该为0x00")
        if not 0 <= octets[0] < 8:
            raise InvalidEncoding("BitString首字节（末尾未用字符）应该为1到7")  # X.690 8.6.2.2
        return octets[1:], octets[0]

    def encode_value(self, value: Tuple[bytes, int]) -> bytes:
        bit_string, unused = value
        if not 0 <= unused < 8:
            raise ValueError("BitString的末尾未用字符应当不超过7个")

        return bytes((unused, )) + bit_string


class ASN1OctetString(ASN1DataType):
    def __init__(self, length: Length = None, value: bytes = None, value_octets: bytes = None, der: bool = False):
        super().__init__(length, value, value_octets, der)

    @classmethod
    def tag(cls) -> Tag:
        return TAG_OctetString

    @classmethod
    def tag_name(cls) -> str:
        return 'OctetString'

    def decode_value(self, octets: bytes, der: bool):
        return octets

    def encode_value(self, value) -> bytes:
        return value


class ASN1Null(ASN1DataType):
    def __init__(self, der: bool = False):
        super().__init__(Length.build(0), None, b'')

    @classmethod
    def tag(cls) -> Tag:
        return TAG_Null

    @classmethod
    def tag_name(cls) -> str:
        return 'Null'

    def decode_value(self, octets: bytes, der: bool):
        if octets != b'':
            raise InvalidEncoding('Null值字节必须为空', octets)
        return None

    def encode_value(self, value) -> bytes:
        if value is not None:
            raise UnsupportedValue('Null值必须为None', value)
        return b''


class ASN1ObjectIdentifier(ASN1DataType):
    """X.690 8.19 Object Identifier (OID)

    OID的编码是由子id（subidentifier)编码按顺序链接形成的。
    每个子id可以由字节串表示，其中每个字节的b8表示是否是末尾字节。末尾字节的b8=1，其他字节的b8=0。
    将子id的每个字节的b7-b1链接起来构成的无符号整数即为子id的数值。子id的数值应当以最小数量的字节来编码，那么首字节不应当是0x80。
    子id的数量比OID的元素个数少1个，原因在于最开始的子id是由最开始的2个元素编码而成的。
    令OID的第一个元素为X，第二个元素为Y，则第一个子id为 (X * 40) + Y。
    其他的子元素依次与后续的子id编码相同。
    """
    def __init__(self, length: Length = None, value: Union[str, Sequence[int]] = None,
                 value_octets: bytes = None, der: bool = False):
        super().__init__(length, value, value_octets, der)

    @classmethod
    def tag(cls) -> Tag:
        return TAG_ObjectIdentifier

    @classmethod
    def tag_name(cls) -> str:
        return 'ObjectIdentifier'

    @property
    def oid_string(self):
        return '.'.join((f'{n}' for n in self._value))

    def decode_value(self, octets: bytes, der: bool):
        sub_ids = []
        sn = 0
        for b in octets:
            if sn == 0 and b == 0x80:
                raise InvalidEncoding("ObjectIdentifier中subidentifier的首字节不能为0x80", octets)
            sn = (sn << 7) | (b & 0x7f)
            if b & 0x80 == 0:
                sub_ids.append(sn)
                sn = 0

        if octets[-1] & 0x80 != 0:
            raise InvalidEncoding("ObjectIdentifier中末尾subidentifier未结束", octets)

        x, y = divmod(sub_ids[0], 40) if sub_ids[0] < 80 else (2, sub_ids[0] - 80)

        return x, y, *sub_ids[1:]

    STRING_PATTERN: re.Pattern = re.compile(r'^[012](\.[0-9]+)+$')

    def encode_value(self, value) -> bytes:
        if isinstance(value, str):
            if not ASN1ObjectIdentifier.STRING_PATTERN.match(value):
                raise ValueError("ObjectIdentifier不正确：{}".format(value))
            oid = [int(item) for item in value.split('.')]
            self._value = tuple(oid)
        else:
            oid = value
        if len(oid) < 2 or (not 0 <= oid[0] < 3) or (not 0 <= oid[1] < 40):
            raise ValueError("ObjectIdentifier不正确：{}".format(value))

        octets = bytearray()
        for comp in reversed((oid[0] * 40 + oid[1], *oid[2:],)):
            octets.append(comp & 0x7f)
            comp >>= 7
            while comp > 0:
                octets.append(comp & 0x7f | 0x80)
                comp >>= 7
        return bytes(reversed(octets))


class ASN1UnicodeString(ASN1DataType):
    """限定类型字符串中Unicode编码的基类，是ASN1UniversalString、ASN1BMPString、ASN1UTF8String的父类。

    X690 8.23 Restricted Character String
    """
    def __init__(self, length: Length = None, value: str = None, value_octets: bytes = None, der: bool = False):
        super().__init__(length, value, value_octets, der)

    @classmethod
    def encoding(cls) -> str:
        """由各子类重写以实现对不同编码的限制"""
        raise NotImplementedError()

    def decode_value(self, octets: bytes, der: bool):
        return octets.decode(self.encoding())

    def encode_value(self, value) -> bytes:
        return value.encode(self.encoding())


class ASN1UTF8String(ASN1UnicodeString):
    """UTF-8编码的限定类型字符串，X 690 8.23.10"""
    def __init__(self, length: Length = None, value=None, value_octets: bytes = None, der: bool = False):
        super().__init__(length, value, value_octets, der)
    @classmethod
    def tag(cls) -> Tag:
        return TAG_UTF8String

    @classmethod
    def tag_name(cls) -> str:
        return 'UTF8String'

    @classmethod
    def encoding(cls) -> str:
        return 'utf-8'


class ASN1UniversalString(ASN1UnicodeString):
    """Unicode编码（UCS-4）编码的限定类型字符串，对应于python中的UTF-32BE，每个字符由4个字节组成。

    X 690 8.23.7
    For the UniversalString type, the octet string shall contain the octets specified in ISO/IEC 10646,
    using the 4-octet canonical form (see 13.2 of ISO/IEC 10646). Signatures shall not be used. Control
    functions may be used provided they satisfy the restrictions imposed by 8.23.9.
    """
    def __init__(self, length: Length = None, value: str = None, value_octets: bytes = None, der: bool = False):
        super().__init__(length, value, value_octets, der)

    @classmethod
    def encoding(cls) -> str:
        return 'utf-32be'

    @classmethod
    def tag(cls) -> Tag:
        return TAG_UniversalString

    @classmethod
    def tag_name(cls) -> str:
        return 'UniversalString'


class ASN1BMPString(ASN1UnicodeString):
    """Basic Multilingual Plane (BMP)区的的限定类型字符串，对应于python中的UTF-16BE，每个字符由4个字节组成。

    X.690 8.23.8
    For the BMPString type, the octet string shall contain the octets specified in ISO/IEC 10646, using
    the 2-octet BMP form (see 13.1 of ISO/IEC 10646). Signatures shall not be used. Control functions may
    be used provided they satisfy the restrictions imposed by 8.23.9.
    """
    def __init__(self, length: Length = None, value: str = None, value_octets: bytes = None, der: bool = False):
        super().__init__(length, value, value_octets, der)

    @classmethod
    def encoding(cls) -> str:
        return 'utf-16be'

    @classmethod
    def tag(cls) -> Tag:
        return TAG_BMPString

    @classmethod
    def tag_name(cls) -> str:
        return 'BMPString'

class ASN1ISO2022String(ASN1DataType):
    """符合ISO/IEC 2022的8-bit字符串

    X.690 8.23.5
    For restricted character strings apart from UniversalString, UTF8String and BMPString, the octet string shall
    contain the octets specified in ISO/IEC 2022 for encodings in an 8-bit environment, using the escape sequence
    and character codings registered in accordance with ISO/IEC 2375.

    根据Wikipedia，ISO 8859系列、GB 2312、ISO-2022-JP等标准均符合ISO/IEC 2022。
    ISO/IEC 2022 Information technology—Character code structure and extension techniques
    https://en.wikipedia.org/wiki/ISO/IEC_2022#Code_structure
    """
    def __init__(self, length: Length = None, value: str = None, value_octets: bytes = None, der: bool = False):
        super().__init__(length, value, value_octets, der)

    @classmethod
    def restrict(cls, value) -> bool:
        """由各子类重写以实现对字符集范围的限制"""
        raise NotImplementedError()

    def decode_value(self, octets: bytes, der: bool):
        string = octets.decode('iso-8859-1')
        if self.restrict(string):
            raise InvalidEncoding('字符串编码不符合{}限制条件'.format(self.__class__), octets)
        return string

    def encode_value(self, value) -> bytes:
        return self._value.encode('iso-8859-1')


class ASN1NumericString(ASN1ISO2022String):
    """仅由数字和空格构成的字符串

    X.680 41 Table 8
    X.680 41.2 Table 9
    """
    def __init__(self, length: Length = None, value: str = None, value_octets: bytes = None, der: bool = False):
        super().__init__(length, value, value_octets, der)

    PATTERN: re.Pattern = re.compile(r'^[0-9 ]*$')
    @classmethod
    def restrict(cls, value) -> bool:
        return ASN1NumericString.PATTERN.match(value) is not None

    @classmethod
    def tag(cls) -> Tag:
        return TAG_NumericString

    @classmethod
    def tag_name(cls) -> str:
        return 'NumericString'


class ASN1PrintableString(ASN1ISO2022String):
    """仅由可打印字符构成的字符串

    X.680 41 Table 8
    X.680 41.4 Table 10
    """
    def __init__(self, length: Length = None, value: str = None, value_octets: bytes = None, der: bool = False):
        super().__init__(length, value, value_octets, der)

    PATTERN: re.Pattern = re.compile(r'^[0-9A-Za-z \'()+,-.\/:=?]*$')
    @classmethod
    def restrict(cls, value) -> bool:
        return ASN1PrintableString.PATTERN.match(value) is not None

    @classmethod
    def tag(cls) -> Tag:
        return TAG_PrintableString

    @classmethod
    def tag_name(cls) -> str:
        return 'PrintableString'


class ASN1VisibleString(ASN1ISO2022String):
    """符合ISO 646标准的字符串，字符范围在0x00-0x7f。

    ISO/IEC 646 is a set of ISO/IEC standards, described as Information technology — ISO 7-bit coded character
    set for information interchange, and developed in cooperation with ASCII at least since 1964.
    """
    def __init__(self, length: Length = None, value: str = None, value_octets: bytes = None, der: bool = False):
        super().__init__(length, value, value_octets, der)

    PATTERN: re.Pattern = re.compile(r'^[\x00-\x7f]*$')
    @classmethod
    def restrict(cls, value) -> bool:
        return ASN1VisibleString.PATTERN.match(value) is not None

    @classmethod
    def tag(cls) -> Tag:
        return TAG_VisibleString

    @classmethod
    def tag_name(cls) -> str:
        return 'VisibleString'


class ASN1GraphicString(ASN1VisibleString):
    """暂时等同于VisibleString

    相关细节待研究开发。
    X.680 41 Table 8
    X.690 8.23.5.2 Table 3
    """
    def __init__(self, length: Length = None, value: str = None, value_octets: bytes = None, der: bool = False):
        super().__init__(length, value, value_octets, der)

    @classmethod
    def tag(cls) -> Tag:
        return TAG_VisibleString

    @classmethod
    def tag_name(cls) -> str:
        return 'VisibleString'

class ASN1GeneralString(ASN1ISO2022String):
    """暂时未做限制的ISO/IEC 2022字符串

    相关细节待研究开发。
    X.680 41 Table 8
    X.690 8.23.5.2 Table 3
    """
    def __init__(self, length: Length = None, value: str = None, value_octets: bytes = None, der: bool = False):
        super().__init__(length, value, value_octets, der)

    @classmethod
    def restrict(cls, value) -> bool:
        return True

    @classmethod
    def tag(cls) -> Tag:
        return TAG_GeneralString

    @classmethod
    def tag_name(cls) -> str:
        return 'GeneralString'


class ASN1IA5String(ASN1GeneralString):
    """暂时未做限制的ISO/IEC 2022字符串

    相关细节待研究开发。
    X.680 41 Table 8
    X.690 8.23.5.2 Table 3
    """
    def __init__(self, length: Length = None, value: str = None, value_octets: bytes = None, der: bool = False):
        super().__init__(length, value, value_octets, der)

    @classmethod
    def tag(cls) -> Tag:
        return TAG_IA5String

    @classmethod
    def tag_name(cls) -> str:
        return 'IA5String'

_YEAR_G = r'(?P<year>[0-9]{4})'
_YEAR_U = r'(?P<year>[0-9]{2})'
_MONTH = r'(?P<month>0[1-9]|1[0-2])'
_DAY = r'(?P<day>[0-2][0-9]|3[01])'
_HOUR = r'(?P<hour>[01][0-9]|2[0-3])'
_MINUTE = r'(?P<minute>[0-5][0-9])'
_SECOND = r'(?P<second>[0-5][0-9])'
_FRACTION = r'(?P<fraction>\.[0-9]+)'
_TIMEZONE = r'(?P<tz>Z|(?P<tzsign>[+-])(?P<tzhour>0[0-9]|1[0-2])(?P<tzminute>[0-5][0-9])?)'

class ASN1GeneralizedTime(ASN1DataType):
    """通用时间

    X.680 46 Generalized Time
    X.690 11.7 GeneralizedTime
    """
    def __init__(self, length: Length = None, value: datetime = None, value_octets: bytes = None, der: bool = False):
        super().__init__(length, value, value_octets, der)

    DATETIME_PATTERN = re.compile(f'^{_YEAR_G}{_MONTH}{_DAY}{_HOUR}{_MINUTE}?{_SECOND}?{_FRACTION}?{_TIMEZONE}?$')

    @classmethod
    def tag(cls) -> Tag:
        return TAG_GeneralizedTime

    @classmethod
    def tag_name(cls) -> str:
        return 'GeneralizedTime'

    def decode_value(self, octets: bytes, der: bool):
        dt_str = octets.decode('utf-8')
        m = ASN1GeneralizedTime.DATETIME_PATTERN.match(dt_str)
        if m is None:
            raise ValueError(f"无法识别的通用时间（Generalized Time）: {dt_str}")

        year, month, day, hour, minute, second, fraction, tz, tzsign, tzhour, tzminute = m.groups()

        if der:
            if not second:
                # 11.7.2 The seconds element shall always be present.
                raise DERIncompatible('GeneralizedTime必须要准确到秒（X.690 11.7.2）')
            if not tz:
                # 11.7.1 The encoding shall terminate with a "Z", as described in the Rec. ITU-T X.680 | ISO/IEC 8824-1
                # clause on GeneralizedTime.
                raise DERIncompatible('GeneralizedTime必须以Z结尾（X.690 11.7.1）')

        if fraction:
            if second is None:
                if minute is None:
                    frac_delta = timedelta(hours=float(fraction))
                else:
                    frac_delta = timedelta(minutes=float(fraction))
            else:
                frac_delta = timedelta(seconds=float(fraction))
        else:
            frac_delta = None

        if tz == 'Z':
            tz_delta = None
        else:
            if der:
                # 11.7.1 The encoding shall terminate with a "Z", as described in the Rec. ITU-T X.680 | ISO/IEC 8824-1
                # clause on GeneralizedTime.
                raise DERIncompatible('GeneralizedTime必须以Z结尾（X.690 11.7.1')
            # 本地时转化为GMT，注意-XX（西XX区）要加时刻、+XX（东时区）要减时刻
            tz_delta = timedelta(hours=int(tzhour) if tzhour else 0,
                                 minutes=int(tzminute) if tzminute else 0) * (1 if tzsign == '-' else -1)

        dt_value = datetime(year=int(year), month=int(month), day=int(day),
                               hour=int(hour), minute=int(minute) if minute else 0,
                               second=int(second) if second else 0)
        if frac_delta:
            dt_value += frac_delta
        if tz_delta:
            dt_value += tz_delta
        return dt_value

    def encode_value(self, value) -> bytes:
        if value.tzinfo:
            value = value.astimezone(timezone.utc)
        if value.microsecond == 0:
            res = value.strftime("%Y%m%d%H%M%SZ")
        else:
            res = value.strftime("%Y%m%d%H%M%S.%fZ")
        return res.encode('utf-8')


class ASN1UTCTime(ASN1DataType):
    """UTC时间

    X.680 47 Universal Time
    X.690 11.8 UTCTime
    """
    def __init__(self, length: Length = None, value: datetime = None, value_octets: bytes = None, der: bool = False):
        super().__init__(length, value, value_octets, der)

    DATETIME_PATTERN = re.compile(f'^{_YEAR_U}{_MONTH}{_DAY}{_HOUR}{_MINUTE}{_SECOND}?{_TIMEZONE}$')

    @classmethod
    def tag(cls) -> Tag:
        return TAG_UTCTime

    @classmethod
    def tag_name(cls) -> str:
        return 'UTCTime'

    def decode_value(self, octets: bytes, der: bool):
        dt_str = octets.decode('utf-8')
        m = ASN1UTCTime.DATETIME_PATTERN.match(dt_str)
        if m is None:
            raise ValueError(f"无法识别的UTC时间（Generalized Time）: {dt_str}")

        year, month, day, hour, minute, second, tz, tzsign, tzhour, tzminute = m.groups()

        if der:
            if not second:
                # 11.8.2 The seconds element shall always be present.
                raise DERIncompatible('UTCTime必须要准确到秒（X.690 11.8.2）')
            if not tz:
                # 11.8.1 The encoding shall terminate with "Z", as described in the ITU-T X.680 | ISO/IEC 8824-1
                # clause on UTCTime
                raise DERIncompatible('UTCTime必须以Z结尾（X.690 11.8.1）')

        if tz == 'Z':
            tz_delta = None
        else:
            # 11.8.1 The encoding shall terminate with "Z", as described in the ITU-T X.680 | ISO/IEC 8824-1
            # clause on UTCTime
            if der:
                raise DERIncompatible('UTCTime必须以Z结尾（X.690 11.8.1）')
            tz_delta = timedelta(hours=int(tzhour) if tzhour else 0,
                                 minutes=int(tzminute) if tzminute else 0) * (1 if tzsign == '-' else -1)

        dr_value = datetime(year=int(2000 + int(year) if int(year) < 70 else 1900 + int(year)),
                               month=int(month), day=int(day),
                               hour=int(hour), minute=int(minute),
                               second=int(second) if second else 0)
        if tz_delta:
            dr_value += tz_delta
        return dr_value

    def encode_value(self, value) -> bytes:
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc)
        return value.strftime('%y%m%d%H%M%SZ').encode('utf-8')


class ASN1Sequence(ASN1DataType):
    def __init__(self, length: Length = None, value: Sequence[ASN1DataType] = None, value_octets: bytes = None,
                 der: bool = False):
        super().__init__(length, value, value_octets, der)

    @classmethod
    def tag(cls) -> Tag:
        return TAG_Sequence

    @classmethod
    def tag_name(cls) -> str:
        return 'Sequence'

    def decode_value(self, octets: bytes, der: bool):
        # TODO
        pass

    def encode_value(self, value) -> bytes:
        # TODO
        pass