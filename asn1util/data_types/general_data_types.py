from asn1util.codec import *
from typing import List, Sequence

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

    @property
    def tag(self) -> Tag:
        """返回数据对象标签"""
        raise NotImplementedError()

    @property
    def tag_name(self) -> str:
        """返回数据对象名称"""
        raise NotImplementedError()

    @property
    def length(self) -> Length:
        return self._length

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
        buffer = bytearray(self.tag.octets)
        buffer.extend(self._length.octets)
        buffer.extend(self._value_octets)
        return bytes(buffer)

    def __eq__(self, other):
        return (self.tag == other.tag and self._length == other.length
                and self.value == other.value)

    def _repr_common_format(self, meta_expr = None, value_expr = None):
        # return ('[{}](length={}){}        ({} {} {})'
        #         .format(self.tag_name, self._length.value, value_expr,
        #                 self.tag.octets.hex().upper(), self._length.octets.hex().upper(),
        #                 self._value_octets.hex().upper()))
        if meta_expr is None:
            meta_expr = f'(len={self._length.value})'
        if value_expr is None:
            value_expr = ''
        return ('[{}]{}{}'
                .format(self.tag_name, meta_expr, value_expr))

    def __repr__(self):
        return self._repr_common_format(self._value)


class ASN1GeneralDataType(ASN1DataType):
    """通用的未专门化的ASN.1元素类型"""
    def __init__(self, tag: Tag, length: Length = None, value: bytes = None, value_octets: bytes = None, der: bool = False):
        self._tag = tag
        super().__init__(length, value, value_octets, der)

    @property
    def tag(self) -> Tag:
        return self._tag

    @property
    def tag_name(self) -> str:
        return f'General({repr(self._tag)})'

    def decode_value(self, octets: bytes, der: bool) -> Union[bytes, List[ASN1DataType]]:
        if self._tag.is_primitive:
            return octets
        else:
            return asn1_decode(octets, der)

    def encode_value(self, value) -> bytes:
        return value

    def __repr__(self):
        if self._tag.is_primitive:
            return self._repr_common_format(value_expr=self._value.hex().upper())
        else:
            return self._repr_common_format(meta_expr=f'(len={self._length.value},items={len(self._value)})',
                                            value_expr='')

UNIVERSAL_DATA_TYPE_MAP = {}
EXTENDED_DATA_TYPE_MAP = {}


def asn1_decode(data: Union[bytes, bytearray, BinaryIO], der: bool = False) -> List[ASN1DataType]:
    res = []
    for t, l, v in iter_tlvs(data, in_octets=False):
        if t.octets in UNIVERSAL_DATA_TYPE_MAP:
            item = UNIVERSAL_DATA_TYPE_MAP[t.octets](length=l, value_octets=v, der=der)
        elif t.octets in EXTENDED_DATA_TYPE_MAP:
            item = EXTENDED_DATA_TYPE_MAP[t.octets](length=l, value_octets=v, der=der)
        else:
            item = ASN1GeneralDataType(tag=t, length=l, value_octets=v)
        res.append(item)
    return res


def asn1_encode(data: Union[ASN1DataType, Sequence[ASN1DataType], Generator[ASN1DataType]]) -> bytes:
    if isinstance(data, ASN1DataType):
        return data.octets
    if isinstance(data, Sequence) or isinstance(data, Generator):
        buffer = bytearray()
        for item in data:
            buffer.extend(item.octets)
        return bytes(buffer)