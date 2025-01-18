from .valueclasses import *
from .tlv import *
from .oid import *
from .real import *
from contextlib import contextmanager
from functools import partial
from typing import *


VALUE_TYPE_ENCODERS = {
    TagNumber.ASN1EndOfContent: (lambda value: b''),
    TagNumber.Boolean: BooleanValue.encode,
    TagNumber.Integer: signed_int_to_bytes,
    TagNumber.BitString: BitString.encode,
    TagNumber.OctetString: (lambda value: value),
    TagNumber.Null: (lambda value: b''),
    TagNumber.ObjectIdentifier: ObjectIdentifier.encode,
    # ObjectDescriptor
    # External
    TagNumber.Real: Real.encode,
    TagNumber.Enumerated: signed_int_to_bytes,
    # RelativeOID
    TagNumber.Time: None,
    # Sequence
    # Set
    TagNumber.GeneralizedTime: GeneralizedTime.encode,
    TagNumber.UTCTime: UTCTime.encode,
    TagNumber.Date: None,
    TagNumber.TimeOfDay: None,
    TagNumber.DateTime: GeneralizedTime.encode,
    TagNumber.Duration: None
}

for tn in RESTRICTED_STRING_TAGS:
    VALUE_TYPE_ENCODERS[tn] = partial(RestrictedString.encode, tag_number=tn)


class Encoder:
    def __init__(self):
        self._stack = []
        self._data = bytearray()

    def append_primitive(self, tag: Tuple[bytes, Tag], value: bytes):
        if isinstance(tag, bytes):
            tag = Tag.decode(tag)
        self._recursive_return(tag, value)

    def append_encoded_primitive(self, tag_number: int, tag_class: TagClass = TagClass.UNIVERSAL, value: bytes = None, **kwargs):
        tag = Tag.build(tag_class, TagPC.PRIMITIVE, tag_number)
        tn = TagNumber(tag_number)
        if value is not None:
            encoded = value
        elif tn in VALUE_TYPE_ENCODERS:
            encoded = VALUE_TYPE_ENCODERS[tn](**kwargs)
        else:
            raise NotImplementedError(tn)

        self._recursive_return(tag, encoded)

    def begin_constructed(self, tag_octets: bytes = None, tag_number: int = 0, tag_class: TagClass = TagClass.UNIVERSAL):
        """
        开始构造Constructed类型元素，将Tag和对应的字节数组压栈。
        :param tag_octets:
        :param tag_number:
        :param tag_class:
        :return:
        """
        if tag_octets is None:
            tag = Tag.build(tag_class, TagPC.CONSTRUCTED, tag_number)
        else:
            tag = Tag.decode(tag_octets)
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

    @contextmanager
    def construct(self, tag_number: int, tag_class: TagClass = TagClass.UNIVERSAL):
        self.begin_constructed(tag_number, tag_class)
        try:
            yield
        finally:
            self.end_constructed()

    def _recursive_return(self, tag: Tag, value: bytes):
        """根据Tag和Value计算Length，构造元素数据段。

        如果没有上级Constructed元素，则将元素数据段附到数据流中。
        如果有，则将元素数据段附到上级元素的值数据中。
        :param tag:
        :param value:
        :return:
        """
        # assert isinstance(value, bytes)
        length = Length.build(len(value))
        segment = bytearray()
        segment.extend(tag.octets)
        segment.extend(length.octets)
        segment.extend(value)
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
