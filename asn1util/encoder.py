from .encoding import *
from .tlv import *
from .oid import *
from .real import *


class NotSupportedValueException(ASN1EncodingException):
    def __init__(self, value):
        self.message = f'Value {value} of type {type(value)} is not supported.'


def encode_boolean(value: Union[bool, int]):
    if isinstance(value, bool):
        return b'\xff' if value else b'\x00'
    if isinstance(value, int):
        return b'\xff' if value != 0 else b'\x00'
    raise NotSupportedValueException(value)


TAG_HANDLERS = {
    TagNumber.EndOfContent: (lambda: b''),
    TagNumber.Boolean: encode_boolean,
    TagNumber.Integer: signed_int_to_bytes,
    TagNumber.BitString: encode_bit_string,
    TagNumber.OctetString: (lambda value: value),
    TagNumber.Null: (lambda: b''),
    TagNumber.Enumerated: signed_int_to_bytes,
    TagNumber.UTF8String: (lambda value: value.encode('utf-8')),
    TagNumber.UniversalString: (lambda value: value.encode('utf-32')),
    TagNumber.BMPString: encode_bmp_string,
    TagNumber.ObjectIdentifier: ObjectIdentifier.encode,
    TagNumber.Real: Real.encode,
    TagNumber.GeneralizedTime: encode_generalized_time,
    TagNumber.UTCTime: encode_utc_time,
    TagNumber.Time: encode_time,
    TagNumber.TimeOfDay: encode_time,
    TagNumber.Date: encode_date,
    TagNumber.DateTime: encode_generalized_time,
    TagNumber.Duration: encode_duration
}


class Encoder:
    def __init__(self):
        self._stack = []
        self._data = bytearray()

    def append_primitive(self, tag_number: int, tag_class: TagClass = TagClass.UNIVERSAL, **kwargs):
        tag = Tag(tag_class, TagPC.PRIMITIVE, tag_number)
        tn = TagNumber(tag_number)
        if tn in TAG_HANDLERS:
            encoded = TAG_HANDLERS[tn](**kwargs)
        else:
            raise NotImplementedError(tn)

        self._recursive_return(tag, encoded)

    def begin_constructed(self, tag_number: int, tag_class: TagClass = TagClass.UNIVERSAL):
        """
        开始构造Constructed类型元素，将Tag和对应的字节数组压栈。
        :param tag_number:
        :param tag_class:
        :return:
        """
        tag = Tag(tag_class, TagPC.CONSTRUCTED, tag_number)
        self._stack.append((tag, bytearray()))

    def end_constructed(self):
        """
        完成构造Constructed类型元素。
        将Tag和Value退栈，调用_recursive_return处理元素。
        :return:
        """
        if len(self._stack) == 0:
            raise ASN1EncodingException('No begin_constructed() with end_constructed()')
        tag, value = self._stack.pop()
        self._recursive_return(tag, value)

    def _recursive_return(self, tag: Tag, value: bytes):
        """
        根据Tag和Value计算Length，构造元素数据段。
        如果没有上级Constructed元素，则将元素数据段附到数据流中。
        如果有，则将元素数据段附到上级元素的值数据中。
        :param tag:
        :param value:
        :return:
        """
        length = Length(len(value))
        segment = tag.octets + length.octets + value
        if len(self._stack) == 0:
            self._data.extend(segment)
        else:
            self._stack[-1][1].extend(segment)

    @property
    def data(self):
        if len(self._stack) == 0:
            return bytes(self._data)
        else:
            raise ASN1EncodingException('Constructed element has not finished.')
