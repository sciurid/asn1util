from enum import IntEnum
from .exceptions import *
from typing import BinaryIO, Union
import logging
from io import BytesIO

logger = logging.getLogger(__name__)







# class TagNumber(IntEnum):
#     EndOfContent = 0x00
#     Boolean = 0x01
#     Integer = 0x02
#     BitString = 0x03
#     OctetString = 0x04
#     Null = 0x05
#     ObjectIdentifier = 0x06
#     ObjectDescriptor = 0x07
#     External = 0x08
#     Real = 0x09
#     Enumerated = 0x0a
#     UTF8String = 0x0c
#     RelativeOID = 0x0d
#     Time = 0x0e
#     Sequence = 0x10
#     Set = 0x11
#     NumericString = 0x12
#     PrintableString = 0x13
#     TeletexString = 0x14  # T61String
#     VideotexString = 0x15
#     IA5String = 0x16
#     UTCTime = 0x17
#     GeneralizedTime = 0x18
#     GraphicString = 0x19
#     VisibleString = 0x1a  # ISO646String
#     GeneralString = 0x1b
#     UniversalString = 0x1c  # UTF8String
#     BMPString = 0x1e
#     Date = 0x1f
#     TimeOfDay = 0x20
#     DateTime = 0x21
#     Duration = 0x22


# """
# 字符串类别
# """
# RESTRICTED_STRING_TAGS = (
#     TagNumber.UTF8String, TagNumber.NumericString, TagNumber.PrintableString, TagNumber.TeletexString,
#     TagNumber.VideotexString, TagNumber.IA5String, TagNumber.GraphicString, TagNumber.VisibleString,
#     TagNumber.GeneralString, TagNumber.UniversalString, TagNumber.BMPString
# )
#
#
# TagNumber.values = set(item.value for item in TagNumber)
# TagNumber.primitive_set = {
#     TagNumber.EndOfContent, TagNumber.Boolean, TagNumber.Integer, TagNumber.BitString,
#     TagNumber.OctetString, TagNumber.Null, TagNumber.ObjectIdentifier,
#     TagNumber.ObjectDescriptor, TagNumber.Real, TagNumber.Enumerated, TagNumber.UTF8String,
#     TagNumber.RelativeOID, TagNumber.Time, TagNumber.NumericString, TagNumber.PrintableString,
#     TagNumber.TeletexString, TagNumber.IA5String, TagNumber.UTCTime, TagNumber.GeneralizedTime,
#     TagNumber.UniversalString, TagNumber.Date, TagNumber.TimeOfDay, TagNumber.DateTime,
#     TagNumber.Duration}
# TagNumber.constructed_set = {
#     TagNumber.BitString, TagNumber.OctetString, TagNumber.ObjectDescriptor,
#     TagNumber.UTF8String, TagNumber.Sequence, TagNumber.Set, TagNumber.NumericString,
#     TagNumber.PrintableString, TagNumber.TeletexString, TagNumber.IA5String, TagNumber.UTCTime,
#     TagNumber.GeneralizedTime, TagNumber.UniversalString}


class Tag:
    """处理标签（Tag）格式的类

    X.690 8.1.2
    Tag格式由三个属性组成：类别（Class）、原始（Primitive）或组合（Constructed）类型、数值（Number）
    """
    class Class(IntEnum):
        """
        标签类别（tag class）：X.690 8.1.2.2 规定，标签数据的首字节的b8、b7标记标签类别
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

    class Type(IntEnum):
        """
        标签类型（tag type）：X.690 8.1.2.5 规定，标签数据的首字节的b6标记标签类型
        0：基本类型
        1：构造类型
        """
        PRIMITIVE = 0x00
        CONSTRUCTED = 0x20

    def __init__(self, octets: bytes, strict=False):
        """使用表示标签的字节串数据来构造Tag对象

        :param octets: 表示标签的字节串数据
        :param strict: 是否严格检查标签数值和长短表示形式的对应关系
        """

        # X.690 8.1.2.3
        tag_len = len(octets)  # 总长度
        if tag_len == 0:
            raise InvalidEncoding('标签字节为空/Tag octets is empty')

        leading = octets[0]  # 首字节
        self._octets = octets
        self._clazz = Tag.Class(leading & 0xC0)  # b8b7指示类Class
        self._pc = Tag.Type(leading & 0x20)  # b6指示基本类型或构造类型P/C

        # X.690 8.1.2.4
        if leading & 0x1f < 0x1f:  # 短表示形式
            self._number = leading & 0x1f
        else:  # 长表示形式
            if tag_len == 1:
                raise InvalidEncoding('首字节b5-b1为11111但没有后续字节/'
                                      'Leading byte b5-b1=11111 without following octets', octets)
            self._number = 0
            for ind, octet in enumerate(octets[1:], 1):
                if ind == 1 and octet & 0x3f == 0:  # 首个后续字节的b7-b1不能全为0
                    raise InvalidEncoding('首个后续字节的b7-b1全为0/'
                                          'First subsequent byte with b7-b1 all 0', octets)
                if ind == tag_len - 1:  # 末字节
                    if octet & 0x80 != 0:
                        raise InvalidEncoding('末字节的b8为1', octets)
                elif octet & 0x80 == 0:
                    raise InvalidEncoding('非末字节的b8为0', octets)
            if strict and self._number < 0x1f:
                raise InvalidEncoding('首字节b5-b1为11111但标签数值小于31', octets)


    @property
    def clazz(self) -> Class:
        return self._clazz

    @property
    def type(self) -> Type:
        return Tag.Type(self._octets[0] & 0x20)

    @property
    def is_primitive(self) -> bool:
        return self.type == Tag.Type.PRIMITIVE

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

    def __eq__(self, other: 'Tag'):
        return self._octets == other._octets

    def __hash__(self):
        return hash(self._octets)

    TAG_CLASS_ABBR = {
        Class.UNIVERSAL: 'U',
        Class.APPLICATION: 'A',
        Class.CONTEXT_SPECIFIC: 'C',
        Class.PRIVATE: 'P'
    }

    def __str__(self):
        # TODO
        tc = Tag.TAG_CLASS_ABBR[self.clazz]
        tt = 'P' if self.is_primitive else 'C'
        # tn = TagNumber(self.number).name if (self.clazz == Tag.Class.UNIVERSAL and self.number in TagNumber.values) else ''
        return f'{tc}{tt}|({repr(self)})'

    @staticmethod
    def build(the_class: Class, the_type: Type, number: int) -> 'Tag':
        """通过指定元素构造Tag对象（较少使用）

        :param the_class: Tag的类别
        :param the_type: 基本类型或构造类型
        :param number: Tag数值
        """
        tag_initial = the_class | the_type
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
        """从字节串或者流的头部读取出Tag（常用）

        :param data:输入的字节串或流
        """
        if isinstance(data, bytes) or isinstance(data, bytearray):
            data = BytesIO(data)
        leading = data.read(1)
        if len(leading) == 0:  # EOF of data
            return None

        if leading[0] & 0x1f != 0x1f:  # Low tag number form
            return Tag(leading)

        buffer = bytearray()
        buffer.append(leading[0])
        while leading := data.read(1):
            buffer.extend(leading)
            if leading[0] & 0x80 == 0:
                break

        return Tag(bytes(buffer))


class Length:
    INDEFINITE = 0x80
    # X.690 8.1.3.6 不确定长度格式
    # 仅限用于结构类型的标签，以End-of-contents（0x0000）元素结束数据（X.690 8.1.5）

    def __init__(self, octets: bytes, der: bool = False):
        seg_len = len(octets)
        if seg_len == 0:
            raise InvalidEncoding('长度字节为空/Tag octets is empty', octets)

        self._octets = octets
        leading = self._octets[0]

        if leading == Length.INDEFINITE:
            if der:
                raise DERIncompatible(f"DER格式不支持不定长格式/Indefinite length is not supported in DER.", octets)
            self._value = None
        elif leading & 0x80 == 0:  # 短格式（X.690 8.1.3.4）
            if seg_len != 1:
                raise InvalidEncoding("短格式不是单字节表示/Not a single octet for a short form length.", octets)
            self._value = leading & 0x7f
        else:  # 长格式（X.690 8.1.3.5）
            if leading == 0xff:
                raise InvalidEncoding("长格式首字节是0xff/Leading octet 0xff for a long form length.", octets)
            if seg_len != (leading & 0x7f) + 1:
                raise InvalidEncoding("长格式首字节表示的后续字节数{0:d}与实际字节数{1:d}不对应/"
                                      "Leading octet indicating count {0:d}not match subsequent {1:d} octets."
                                      .format(leading & 0x7f, seg_len), octets)
            self._value = int.from_bytes(self._octets[1:], byteorder='big', signed=False)

    @staticmethod
    def build(length_value: int) -> 'Length':
        if length_value is None:
            return Length(bytes([Length.INDEFINITE]))
        if length_value < 0:
            raise ValueError('长度{0:d}小于0/Length value {0:d} is negative'.format(length_value))

        if length_value < 127:
            return Length(bytes([length_value]))
        else:
            num_octets = (length_value.bit_length() + 7) // 8
            if num_octets > 127:
                raise InvalidTLV("长度要求的字节数{0:d}大于127/Number of octets for length value {0:d} is over 127"
                                 .format(num_octets))

            buffer = bytearray([num_octets | 0x80])
            buffer.extend(length_value.to_bytes(num_octets, byteorder='big', signed=False))
            return Length(bytes(buffer))

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

    def __int__(self) -> int:
        return self._value

    @staticmethod
    def decode(data: Union[bytes, bytearray, BinaryIO], der: bool = False) -> 'Length':
        """从字节串或者流的头部读取出Length（常用）

        :param data:输入的字节串或流
        """
        if isinstance(data, bytes) or isinstance(data, bytearray):
            data = BytesIO(data)
        leading = data.read(1)
        if len(leading) == 0:
            return None

        initial = leading[0]
        if leading[0] == 0x80:  # 不确定长度格式
            return Length(leading)
        elif initial & 0x80 == 0:  # 短格式
            return Length(leading)
        else:  # 长格式
            buffer = bytearray(leading)
            subsequent_len = initial & 0x7f
            subsequent_octets = data.read(subsequent_len)
            if len(subsequent_octets) < subsequent_len:
                raise InvalidTLV("剩余字节数{0:d}不足长度{1:d}/Insufficient octets {0:d} < {1:d}"
                                 .format(len(subsequent_octets), subsequent_len))
            buffer.extend(subsequent_octets)
            return Length(bytes(buffer), der)

    def __repr__(self):
        if self.is_definite:
            return f"{self._value}"
        else:
            return "INDEFINITE"


# class Value:
#     def __init__(self, octets: bytes):
#         assert isinstance(octets, bytes)
#         self._octets = octets
#         self._value = None
#
#     def __getitem__(self, index):
#         return self._octets[index]
#
#     def __len__(self):
#         return len(self._octets)
#
#     def __repr__(self):
#         return self._octets.hex(' ')
#
#     @property
#     def octets(self):
#         return self._value
#
#     def __str__(self):
#         return str(self._value)

