from ..data_types import *
from contextlib import contextmanager

logger = logging.getLogger()

class StreamEncoder:
    def __init__(self, stream: BinaryIO = None):
        self._stack = []
        self._stream = stream if stream else BytesIO()

    def append_primitive(self, t: Union[bytes, Tag], value: bytes):
        """对基本元素进行编码并写入缓冲区

        注意：方法仅检查ASN.1元素的TLV合法性，不检查元素的语义合法性。
        """
        tag = Tag(t) if isinstance(t, bytes) else t
        if not tag.is_primitive:
            raise ValueError("组合元素不应调用基本元素的构造函数")

        length = Length.eval(len(value))
        output = self._stream if len(self._stack) == 0 else self._stack[-1][2]
        output.write(tag.octets)
        output.write(length.octets)
        output.write(value)

    def begin_constructed(self, t: Union[bytes, Tag], indefinite_length: bool = False):
        """开始构造组合类型元素
        """
        tag = Tag(t) if isinstance(t, bytes) else t
        if tag.is_primitive:
            raise ValueError("基本元素不应调用组合元素的构造函数")

        output = self._stream if len(self._stack) == 0 else self._stack[-1][2]

        if indefinite_length:
            output.write(Tag(tag.octets).octets)
            output.write(bytes([Length.INDEFINITE]))
        else:
            output.write(Tag(tag.octets).octets)
        # 将组合元素标签、是否不定长、值域缓冲区（如果定长）压入
        self._stack.append((tag, indefinite_length, output if indefinite_length else BytesIO()))

    def end_constructed(self):
        """结束构造Constructed类型元素。
        """
        tag, ind_len, output = self._stack.pop()

        if ind_len:  # 父元素不定长
            output.write(b'\x00\x00')  # 写入EOC，结束组合元素
            return

        octets = output.getvalue()
        length = Length.eval(len(octets))
        if len(self._stack) == 0:
            self._stream.write(length.octets)
            self._stream.write(octets)
        else:
            output = self._stack[-1][2]
            output.write(length.octets)
            output.write(octets)

    @contextmanager
    def construct(self, t: Union[bytes, Tag], indefinite_length: bool = False):
        self.begin_constructed(t, indefinite_length)
        try:
            yield
        finally:
            self.end_constructed()

    @property
    def data(self):
        if len(self._stack) == 0:
            return self._stream.getvalue()
        else:
            raise ASN1Exception("组合元素构造尚未完成")


    def append_boolean(self, value: bool) -> None:
        item = ASN1_TRUE if value else ASN1_FALSE
        return self.append_primitive(item.tag, item.value_octets)

    def append_integer(self, value: int) -> None:
        item = ASN1Integer(value)
        return self.append_primitive(item.tag, item.value_octets)

    def append_real(self, value: Union[int, float, Decimal], base=None) -> None:
        item = ASN1Real(value, base=base)
        return self.append_primitive(item.tag, item.value_octets)

    def append_bit_string(self, value: bytes, bit_length=None, unused_bit=None) -> None:
        if bit_length is None:
            if unused_bit is None:
                uud = 0
            else:
                uud = unused_bit
        else:
            if unused_bit is None:
                uud = len(value) * 8 - bit_length
            else:
                assert bit_length + unused_bit == len(value)
                uud = unused_bit

        item = ASN1BitString((value, uud))
        return self.append_primitive(item.tag, item.value_octets)

    def append_octet_string(self, value: bytes):
        item = ASN1OctetString(value)
        return self.append_primitive(item.tag, item.value_octets)

    def append_bytes(self, value: Union[bytes, bytearray, BinaryIO]) -> None:
        the_value = value if isinstance(value, bytes) \
            else bytes(value) if isinstance(value, bytearray) \
            else value.read()
        return self.append_octet_string(the_value)

    def append_null(self):
        return self.append_primitive(ASN1_NULL.tag, ASN1_NULL.value_octets)

    def append_object_identifier(self, value: Union[str, Sequence[int]]):
        item = ASN1ObjectIdentifier(value)
        return self.append_primitive(item.tag, item.value_octets)

    def append_utf8_string(self, value: str):
        item = ASN1UTF8String(value)
        return self.append_primitive(item.tag, item.value_octets)

    def append_universal_string(self, value: str):
        item = ASN1UniversalString(value)
        return self.append_primitive(item.tag, item.value_octets)

    def append_ucs4_string(self, value: str):
        return self.append_universal_string(value)

    def append_bmp_string(self, value: str):
        item = ASN1BMPString(value)
        return self.append_primitive(item.tag, item.value_octets)

    def append_ucs2_string(self, value: str):
        return self.append_bmp_string(value)

    def append_numeric_string(self, value: str):
        item = ASN1NumericString(value)
        return self.append_primitive(item.tag, item.value_octets)

    def append_printable_string(self, value: str):
        item = ASN1PrintableString(value)
        return self.append_primitive(item.tag, item.value_octets)

    def append_visiable_string(self, value: str):
        item = ASN1VisibleString(value)
        return self.append_primitive(item.tag, item.value_octets)

    def append_graphic_string(self, value: str):
        item = ASN1GraphicString(value)
        return self.append_primitive(item.tag, item.value_octets)

    def append_object_descriptor(self, value: str):
        item = ASN1ObjectDescriptor(value)
        return self.append_primitive(item.tag, item.value_octets)

    def append_general_string(self, value: str):
        item = ASN1GeneralString(value)
        return self.append_primitive(item.tag, item.value_octets)

    def append_ia5_string(self, value: str):
        item = ASN1IA5String(value)
        return self.append_primitive(item.tag, item.value_octets)

    def append_generalized_time(self, value: datetime):
        item = ASN1GeneralizedTime(value)
        return self.append_primitive(item.tag, item.value_octets)

    def append_utc_time(self, value: datetime):
        item = ASN1UTCTime(value)
        return self.append_primitive(item.tag, item.value_octets)

    def begin_sequence(self, indefinite_length: bool = False):
        self.begin_constructed(TAG_Sequence, indefinite_length)

    @contextmanager
    def within_sequence(self, indefinite_length: bool = False):
        self.begin_sequence(indefinite_length)
        try:
            yield
        finally:
            self.end_constructed()

    def begin_set(self, indefinite_length: bool = False):
        self.begin_constructed(TAG_Set, indefinite_length)

    @contextmanager
    def within_set(self, indefinite_length: bool = False):
        self.begin_set(indefinite_length)
        try:
            yield
        finally:
            self.end_constructed()

