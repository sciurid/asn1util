from asn1util import InvalidEncoding, DERIncompatible
from tlv import Tag, Length
from typing import BinaryIO, Union


class DataType:
    """表示各种数据格式的基类
    """
    def __init__(self, tag: Tag, der: bool = False):
        """初始化函数

        由具体数据格式的表示类调用，调用时确定了数据标签Tag
        """
        self._tag = tag
        self._der = der
        self._length = None
        self._value_octets = None
        self._value = None

    @property
    def value(self):
        return self._value

    def validate_assign(self):
        pass

    def decode_subsequence(self, data: Union[bytes, bytearray, BinaryIO]):
        """解析TLV结构后续数据

        :param data: 字节串或字节流
        """
        self._length = Length.decode(data)  # 首先读取出表示长度的字节
        if isinstance(data, BinaryIO):  # 如果是字节流，则继续往下读取相应字节数的数据部分
            self._value_octets = data.read(self._length)
        else:
            ll = len(self._length)  # 如果是字节串，则从长度字节之后读取相应字节数的数据部分
            self._value_octets = bytes(data[ll:ll + self._length.value])

        self.validate_assign()

    @property
    def octets(self):
        buffer = bytearray(self._tag.octets)
        buffer.extend(self._length.octets)
        buffer.extend(self._value_octets)
        return bytes(buffer)


class EndOfContent(DataType):
    """X.690 8.1.5"""
    def __init__(self, der: bool = False):
        super().__init__(Tag(b'\x00'), der)

    def validate_assign(self):
        if self._der:
            raise DERIncompatible("EOC数据元不符合DER格式/End-of-content is not DER compatible")
        if self._length.value != 0:
            raise InvalidEncoding('EOC数据元长度不为0/End-of-content length should be 0')


class BooleanType(DataType):
    """X.690 """  # TODO
    def __init__(self, der: bool = False):
        super().__init__(Tag(b'\x01'), der)
        self._value = None

    def validate_assign(self):
        if self._value_octets == b'\x00':
            self._value = False
        elif self._value_octets == b'\xff':
            self._value = True
        else:
            if self._der:
                raise DERIncompatible('')  # TODO
            else:
                self._value = True





DATA_TYPES = {
    b'\x00': EndOfContent,
    b'\x01': BooleanType,
}
