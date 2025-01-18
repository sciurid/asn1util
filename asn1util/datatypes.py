from abc import abstractmethod

from asn1util import InvalidEncoding, DERIncompatible, UnsupportedValue
from tlv import Tag, Length
from typing import BinaryIO, Union


class ASN1DataType:
    """表示各种数据格式的基类
    """
    def __init__(self, tag: Tag, length: Length, value=None, value_octets: bytes = None, der: bool = False):
        """通过标签（Tag）、长度（Length）、数值（Value）构建成的ASN.1数据对象

        :param tag: ASN.1数据对象的标签
        :param tag: ASN.1数据对象的长度
        :param value: ASN.1数据对象表示的的数值
        :param value_octets: ASN.1数据对象数值的字节串表示
        :param der: ASN.1数据对象是否符合DER规范

        构建过程中将检查参数一致性。
        """
        self._tag = tag
        self._der = der

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
            if self._value_octets is None:  # 仅有数值，则通过数值计算字节串（通常应当遵循DER编码规则），常用于编码情况
                self._value_octets = self.encode_value(value)
                if length is None:
                    self._length = Length.build(len(value))
                elif len(self._value_octets) != length.value:
                    raise ValueError("数值value编码出的字节串长度与length不一致")
            else:   # 两者都有时，则保留字节串并以此计算数值（考虑到非DER等编码不唯一情况），并与数值核对
                self._value_octets = value_octets
                decoded = self.decode_value(self._value_octets, der)
                if value != decoded:
                    raise ValueError("数值value或数值字节串value_octets不一致")

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
    def octets(self):
        buffer = bytearray(self._tag.octets)
        buffer.extend(self._length.octets)
        buffer.extend(self._value_octets)
        return bytes(buffer)


class ASN1EndOfContent(ASN1DataType):
    """X.690 8.1.5 EOC"""
    def __init__(self, der: bool = False):
        super().__init__(Tag(b'\x00'), None, b'', der)

    @classmethod
    def decode_value(cls, octets: bytes, der: bool):
        if octets != '':
            raise InvalidEncoding('EOC值字节必须为空', octets)
        return None

    @classmethod
    def encode_value(cls, value) -> bytes:
        if value is not None:
            raise UnsupportedValue('EOC值必须为None', value)
        return b''



class ASN1Boolean(ASN1DataType):
    """X.690 8.2 Boolean"""
    def __init__(self, value: bool, der: bool = False):
        super().__init__(Tag(b'\x01'), der)
        self._value = value

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




DATA_TYPES = {
    b'\x00': ASN1EndOfContent,
    b'\x01': ASN1Boolean,
}
