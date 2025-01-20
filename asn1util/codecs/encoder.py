from .basic import *
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
