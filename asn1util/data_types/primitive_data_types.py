import re
import struct
from decimal import Decimal
from datetime import datetime, timedelta, timezone
from .general_data_types import *
from asn1util.data_types.real import (SpecialRealValue, to_decimal_encoding, to_binary_encoding,
                                      int_to_base2_sne, ieee754_double_to_base2_sne, decimal_to_base2_sne,
                                      to_ieee758_double)
from asn1util.exceptions import InvalidEncoding, DERIncompatible, UnsupportedValue
from asn1util.tlv import Tag, Length
from asn1util.util import signed_int_to_bytes

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


class ASN1EndOfContent(ASN1DataType):

    """X.690 8.1.5 EOC"""
    def __init__(self, value: bytes = None, length: Length = None, value_octets: bytes = b'', der: bool = False):
        assert length is None or length.value == 0
        assert value is None or len(value) == 0
        assert value_octets is None or len(value_octets) == 0
        super().__init__(value, length, value_octets, der)
        if der:
            raise DERIncompatible('DER编码中不出现不确定长度和EOC数据对象')

    @property
    def tag(self) -> Tag:
        return TAG_EOC

    @property
    def tag_name(self) -> str:
        return 'EndOfContent'

    def decode_value(self, octets: bytes, der: bool):
        if octets != b'':
            raise InvalidEncoding('EOC值字节必须为空', octets)
        return None

    def encode_value(self, value) -> bytes:
        if value is not None:
            raise UnsupportedValue('EOC值必须为None', value)
        return b''


ASN1_EOC = ASN1EndOfContent()


class ASN1Boolean(ASN1DataType):
    """X.690 8.2 Boolean"""
    def __init__(self, value: bool = None, length: Length = None, value_octets: bytes = None, der: bool = False):
        super().__init__(value, length, value_octets, der)

    @property
    def tag(self) -> Tag:
        return TAG_Boolean

    @property
    def tag_name(self) -> str:
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


ASN1_TRUE = ASN1Boolean(True)
ASN1_FALSE = ASN1Boolean(False)


class ASN1Integer(ASN1DataType):
    """X.690 8.3 Integer"""
    def __init__(self, value: int = None, length: Length = None, value_octets: bytes = None, der: bool = False):
        super().__init__(value, length, value_octets, der)

    @property
    def tag(self) -> Tag:
        return TAG_Integer

    @property
    def tag_name(self) -> str:
        return 'Integer'

    def decode_value(self, octets: bytes, der: bool) -> int:
        if (len(octets) > 1
                and ((octets[0] == 0x00 and octets[1] & 0x80 == 0) or (octets[0] == 0xff and octets[1] & 0x80 == 1))):
            raise InvalidEncoding("Integer数值编码首字节不能全0或全1")
        return int.from_bytes(octets, byteorder='big', signed=True)

    def encode_value(self, value: int) -> bytes:
        return signed_int_to_bytes(value)


class ASN1Enumerated(ASN1Integer):
    """X.690 8.4 Enumerated"""
    def __init__(self, value: int = None, length: Length = None, value_octets: bytes = None, der: bool = False):
        super().__init__(value, length, value_octets, der)

    @property
    def tag(self) -> Tag:
        return TAG_Enumerated

    @property
    def tag_name(self) -> str:
        return 'Enumerated'


class ASN1Real(ASN1DataType):
    """X.690 8.4 Real"""
    def __init__(self, value=None, length: Length = None, value_octets: bytes = None, der: bool = False,
                 base: Optional[int] = None):
        if base:
            if der and base != 2 and base != 10:
                if der:
                    raise DERIncompatible("DER编码实数Real类型仅限底数为2或10")
            elif base not in (2, 8, 16, 10):
                raise ValueError("实数Real类型仅限底数为2或10")
        self._base = base
        super().__init__(value, length, value_octets, der)

    @property
    def tag(self) -> Tag:
        return TAG_Real

    @property
    def tag_name(self) -> str:
        return 'Real'

    def decode_value(self, octets: bytes, der: bool) -> Union[float, Decimal, SpecialRealValue]:
        leading = octets[0]
        if (b8b7 := leading & 0xc0) == 0x00:  # b8b7=0，十进制表示
            # X.690 8.5.8 (P8)
            self._base = 10
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
                e: int = int.from_bytes(octets[1:2], byteorder='big', signed=True)
                n: int = int.from_bytes(octets[2:], byteorder='big')
            elif b2b1 == 0x01:
                e: int = int.from_bytes(octets[1:3], byteorder='big', signed=True)
                n: int = int.from_bytes(octets[3:], byteorder='big')
            elif b2b1 == 0x02:
                e: int = int.from_bytes(octets[1:4], byteorder='big', signed=True)
                n: int = int.from_bytes(octets[4:], byteorder='big')
            else:
                el = int.from_bytes(octets[1:2], byteorder='big', signed=False)
                e: int = int.from_bytes(octets[2:el + 2], byteorder='big', signed=True)
                n: int = int.from_bytes(octets[el + 2:], byteorder='big')

            if (b6b5 := leading & 0x30) == 0x00:
                base = 2
            elif b6b5 == 0x10:
                base = 8
                e = e * 3 + f
            elif b6b5 == 0x20:
                base = 16
                e = e * 4 + f
            else:
                raise InvalidEncoding("二进制底数保留值{}".format(hex(leading)))
            if self._base:
                if base != self._base:
                    raise InvalidEncoding("二进制底数不一致{} != {:d}".format(hex(leading), self._base))
            else:
                self._base = base

            return to_ieee758_double(s, n, e)

    def encode_value(self, value: Union[int, float, Decimal]) -> bytes:
        if srv := SpecialRealValue.check_special_value(value):
            return srv.octets

        if self._base is None:  # 默认采用不损失精度的幂底数
            self._base = 2 if isinstance(value, float) or isinstance(value, int) else 10
        if self._base == 10:
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

    def __repr__(self) -> str:
        return self._repr_common_format(meta_expr=f'(len={self._length.value},base={self._base})',
                                        value_expr=self.value)


class ASN1BitString(ASN1DataType):
    def __init__(self, value: Tuple[bytes, int] = None, length: Length = None, value_octets: bytes = None,
                 der: bool = False):
        super().__init__(value, length, value_octets, der)

    @property
    def tag_name(self) -> str:
        return 'BitString'

    @property
    def tag(self) -> Tag:
        return TAG_BitString

    def __repr__(self) -> str:
        return self._repr_common_format(meta_expr=f'(len={self._length.value},unused={self.value[1]})',
                                        value_expr=self._value[0].hex().upper())

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
        buffer = bytearray()
        buffer.append(unused)
        if unused == 0:
            buffer.extend(bit_string)
        elif unused > 7:
            raise ValueError("BitString的末尾未用字符应当不超过7个")
        else:
            buffer.extend(bit_string[0:-1])
            buffer.append(bit_string[-1] & (~(1 << unused - 1)))

        return bytes(buffer)


class ASN1OctetString(ASN1DataType):
    def __init__(self, value: bytes = None, length: Length = None, value_octets: bytes = None, der: bool = False):
        super().__init__(value, length, value_octets, der)

    @property
    def tag(self) -> Tag:
        return TAG_OctetString

    @property
    def tag_name(self) -> str:
        return 'OctetString'

    def decode_value(self, octets: bytes, der: bool):
        return octets

    def encode_value(self, value) -> bytes:
        return value

    def __repr__(self) -> str:
        return self._repr_common_format(value_expr=self._value.hex().upper())


class ASN1Null(ASN1DataType):
    def __init__(self, value=None, length: Length = None, value_octets: bytes = None, der: bool = False):
        assert length is None or length.value == 0
        assert value is None or len(value) == 0
        assert value_octets is None or len(value_octets) == 0
        super().__init__(length=Length.eval(0), value_octets=b'')

    @property
    def tag(self) -> Tag:
        return TAG_Null

    @property
    def tag_name(self) -> str:
        return 'Null'

    def decode_value(self, octets: bytes, der: bool):
        if octets != b'':
            raise InvalidEncoding('Null值字节必须为空', octets)
        return None

    def encode_value(self, value) -> bytes:
        if value is not None:
            raise UnsupportedValue('Null值必须为None', value)
        return b''


ASN1_NULL = ASN1Null()


class ASN1ObjectIdentifier(ASN1DataType):
    """X.690 8.19 Object Identifier (OID)

    OID的编码是由子id（subidentifier)编码按顺序链接形成的。
    每个子id可以由字节串表示，其中每个字节的b8表示是否是末尾字节。末尾字节的b8=1，其他字节的b8=0。
    将子id的每个字节的b7-b1链接起来构成的无符号整数即为子id的数值。子id的数值应当以最小数量的字节来编码，那么首字节不应当是0x80。
    子id的数量比OID的元素个数少1个，原因在于最开始的子id是由最开始的2个元素编码而成的。
    令OID的第一个元素为X，第二个元素为Y，则第一个子id为 (X * 40) + Y。
    其他的子元素依次与后续的子id编码相同。
    """
    def __init__(self, value: Union[str, Sequence[int]] = None, length: Length = None,
                 value_octets: bytes = None, der: bool = False):
        super().__init__(value, length, value_octets, der)

    @property
    def tag(self) -> Tag:
        return TAG_ObjectIdentifier

    @property
    def tag_name(self) -> str:
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

    def __repr__(self) -> str:
        return self._repr_common_format(meta_expr=f'(len={self._length.value})',
                                        value_expr=self.oid_string)


class ASN1UnicodeString(ASN1DataType):
    """限定类型字符串中Unicode编码的基类，是ASN1UniversalString、ASN1BMPString、ASN1UTF8String的父类。

    X690 8.23 Restricted Character String
    """
    def __init__(self, value: str = None, length: Length = None, value_octets: bytes = None, der: bool = False):
        super().__init__(value, length, value_octets, der)

    @classmethod
    def encoding(cls) -> str:
        """由各子类重写以实现对不同编码的限制"""
        raise NotImplementedError()

    def decode_value(self, octets: bytes, der: bool):
        return octets.decode(self.encoding())

    def encode_value(self, value) -> bytes:
        return value.encode(self.encoding())


class ASN1UTF8String(ASN1UnicodeString):
    """UTF-8 编码的限定类型字符串，X 690 8.23.10"""
    def __init__(self, value=None, length: Length = None, value_octets: bytes = None, der: bool = False):
        super().__init__(value, length, value_octets, der)

    @property
    def tag(self) -> Tag:
        return TAG_UTF8String

    @property
    def tag_name(self) -> str:
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
    def __init__(self, value: str = None, length: Length = None, value_octets: bytes = None, der: bool = False):
        super().__init__(value, length, value_octets, der)

    @classmethod
    def encoding(cls) -> str:
        return 'utf-32be'

    @property
    def tag(self) -> Tag:
        return TAG_UniversalString

    @property
    def tag_name(self) -> str:
        return 'UniversalString'


class ASN1BMPString(ASN1UnicodeString):
    """Basic Multilingual Plane (BMP)区的的限定类型字符串，对应于python中的UTF-16BE，每个字符由4个字节组成。

    X.690 8.23.8
    For the BMPString type, the octet string shall contain the octets specified in ISO/IEC 10646, using
    the 2-octet BMP form (see 13.1 of ISO/IEC 10646). Signatures shall not be used. Control functions may
    be used provided they satisfy the restrictions imposed by 8.23.9.
    """
    def __init__(self, value: str = None, length: Length = None, value_octets: bytes = None, der: bool = False):
        super().__init__(value, length, value_octets, der)

    @classmethod
    def encoding(cls) -> str:
        return 'utf-16be'

    @property
    def tag(self) -> Tag:
        return TAG_BMPString

    @property
    def tag_name(self) -> str:
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
    def __init__(self, value: str = None, length: Length = None, value_octets: bytes = None, der: bool = False):
        super().__init__(value, length, value_octets, der)

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
    def __init__(self, value: str = None, length: Length = None, value_octets: bytes = None, der: bool = False):
        super().__init__(value, length, value_octets, der)

    PATTERN: re.Pattern = re.compile(r'^[0-9 ]*$')
    @classmethod
    def restrict(cls, value) -> bool:
        return ASN1NumericString.PATTERN.match(value) is None

    @property
    def tag(self) -> Tag:
        return TAG_NumericString

    @property
    def tag_name(self) -> str:
        return 'NumericString'


class ASN1PrintableString(ASN1ISO2022String):
    """仅由可打印字符构成的字符串

    X.680 41 Table 8
    X.680 41.4 Table 10
    """
    def __init__(self, value: str = None, length: Length = None, value_octets: bytes = None, der: bool = False):
        super().__init__(value, length, value_octets, der)

    PATTERN: re.Pattern = re.compile(r'^[0-9A-Za-z \'()+,-.\/:=?]*$')
    @classmethod
    def restrict(cls, value) -> bool:
        return ASN1PrintableString.PATTERN.match(value) is None

    @property
    def tag(self) -> Tag:
        return TAG_PrintableString

    @property
    def tag_name(self) -> str:
        return 'PrintableString'


class ASN1VisibleString(ASN1ISO2022String):
    """符合ISO 646标准的字符串，字符范围在0x00-0x7f。

    ISO/IEC 646 is a set of ISO/IEC standards, described as Information technology — ISO 7-bit coded character
    set for information interchange, and developed in cooperation with ASCII at least since 1964.
    """
    def __init__(self, value: str = None, length: Length = None, value_octets: bytes = None, der: bool = False):
        super().__init__(value, length, value_octets, der)

    PATTERN: re.Pattern = re.compile(r'^[\x00-\x7f]*$')
    @classmethod
    def restrict(cls, value) -> bool:
        return ASN1VisibleString.PATTERN.match(value) is not None

    @property
    def tag(self) -> Tag:
        return TAG_VisibleString

    @property
    def tag_name(self) -> str:
        return 'VisibleString'


class ASN1GraphicString(ASN1VisibleString):
    """暂时等同于VisibleString

    相关细节待研究开发。
    X.680 41 Table 8
    X.690 8.23.5.2 Table 3
    """
    def __init__(self, value: str = None, length: Length = None, value_octets: bytes = None, der: bool = False):
        super().__init__(value, length, value_octets, der)

    @property
    def tag(self) -> Tag:
        return TAG_VisibleString

    @property
    def tag_name(self) -> str:
        return 'VisibleString'

class ASN1ObjectDescriptor(ASN1GraphicString):
    """等同于ASN1GraphicString

    X.680 48 The object descriptor type
    """

    def __init__(self, value: str = None, length: Length = None, value_octets: bytes = None, der: bool = False):
        super().__init__(value, length, value_octets, der)

    @property
    def tag(self) -> Tag:
        return TAG_ObjectDescriptor

    @property
    def tag_name(self) -> str:
        return 'ObjectDescriptor'


class ASN1GeneralString(ASN1ISO2022String):
    """暂时未做限制的ISO/IEC 2022字符串

    相关细节待研究开发。
    X.680 41 Table 8
    X.690 8.23.5.2 Table 3
    """
    def __init__(self, value: str = None, length: Length = None, value_octets: bytes = None, der: bool = False):
        super().__init__(value, length, value_octets, der)

    @classmethod
    def restrict(cls, value) -> bool:
        return True

    @property
    def tag(self) -> Tag:
        return TAG_GeneralString

    @property
    def tag_name(self) -> str:
        return 'GeneralString'


class ASN1IA5String(ASN1GeneralString):
    """暂时未做限制的ISO/IEC 2022字符串

    相关细节待研究开发。
    X.680 41 Table 8
    X.690 8.23.5.2 Table 3
    """
    def __init__(self, value: str = None, length: Length = None, value_octets: bytes = None, der: bool = False):
        super().__init__(value, length, value_octets, der)

    @property
    def tag(self) -> Tag:
        return TAG_IA5String

    @property
    def tag_name(self) -> str:
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
    def __init__(self, value: datetime = None, length: Length = None, value_octets: bytes = None, der: bool = False):
        super().__init__(value, length, value_octets, der)

    DATETIME_PATTERN = re.compile(f'^{_YEAR_G}{_MONTH}{_DAY}{_HOUR}{_MINUTE}?{_SECOND}?{_FRACTION}?{_TIMEZONE}?$')

    @property
    def tag(self) -> Tag:
        return TAG_GeneralizedTime

    @property
    def tag_name(self) -> str:
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
    def __init__(self, value: datetime = None, length: Length = None, value_octets: bytes = None, der: bool = False):
        super().__init__(value, length, value_octets, der)

    DATETIME_PATTERN = re.compile(f'^{_YEAR_U}{_MONTH}{_DAY}{_HOUR}{_MINUTE}{_SECOND}?{_TIMEZONE}$')

    @property
    def tag(self) -> Tag:
        return TAG_UTCTime

    @property
    def tag_name(self) -> str:
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

UNIVERSAL_DATA_TYPE_MAP.update({
    b'\x00': ASN1EndOfContent,
    b'\x01': ASN1Boolean,
    b'\x02': ASN1Integer,
    b'\x03': ASN1BitString,
    b'\x04': ASN1OctetString,
    b'\x05': ASN1Null,
    b'\x06': ASN1ObjectIdentifier,
    b'\x07': ASN1ObjectDescriptor,
    b'\x09': ASN1Real,
    b'\x0A': ASN1Enumerated,
    b'\x0C': ASN1UTF8String,
    b'\x12': ASN1NumericString,
    b'\x13': ASN1PrintableString,
    b'\x16': ASN1IA5String,
    b'\x17': ASN1UTCTime,
    b'\x18': ASN1GeneralizedTime,
    b'\x19': ASN1GraphicString,
    b'\x1a': ASN1VisibleString,
    b'\x1b': ASN1GeneralString,
    b'\x1c': ASN1UniversalString,
    b'\x1e': ASN1BMPString,
})

