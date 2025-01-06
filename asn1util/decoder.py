from asn1util import *

from collections.abc import Iterator
from dataclasses import dataclass
from io import BytesIO
from typing import NamedTuple, BinaryIO, Union
import logging
import sys

logger = logging.getLogger(__name__)

TokenOffsets = NamedTuple('TokenOffsets', t=int, l=int, v=int)


@dataclass
class Token:
    tag: Tag
    length: Length
    offsets: TokenOffsets
    value: Union[bytes, memoryview, None]
    parent: Union['Token', None]
    children: Union[list, None]

    def __str__(self):
        return f'{str(self.tag)} {str(self.length)} ' \
               f'({self.offsets.t:d} {self.offsets.l:d} {self.offsets.v:d}) ' \
               f'{self.value.hex(" ") if self.value else None}'


class TokenObserver:
    """Observer模式的Token处理类，通过Decoder.register_observer()注册。"""
    def on_event(self, event: str, token: Token, stack: list):
        assert event in ('begin', 'end')


class Decoder(Iterator):
    """TLV解码器，对数据块或者二进制流进行解码。支持使用iter()迭代访问。"""
    def __init__(self, data: Union[bytes, BinaryIO]):
        super().__init__()
        self._stack = []
        self._current = None
        self._observers = []
        self._top_tokens = []
        if isinstance(data, bytes):
            self._istream = BytesIO(data)
            self._buffer = data
        else:
            self._istream = data
            self._buffer = None

        self._istream.seek(0)
        self._stack = []
        self._current = None
        self._observers = []
        self._top_tokens = []

    def reset(self):
        self._istream.seek(0)
        self._stack = []
        self._current = None
        self._observers = []
        self._top_tokens = []

    @property
    def top_tokens(self):
        return self._top_tokens

    def register_observer(self, obsvr: TokenObserver):
        self._observers.append(obsvr)

    def decode(self):
        while self.proceed_token():
            pass
        return self.top_tokens

    def __next__(self):
        token = self.proceed_token()
        if token:
            return token
        else:
            raise StopIteration

    def proceed_token(self):
        tof = self._istream.tell()  # tag offset
        tag = Tag.decode(self._istream)  # parse tag
        if tag is None:  # EOF of data
            if self._stack:
                raise InvalidTLV(f"数据异常截断导致元素不完整/ Incomplete TLV due to data truncation: {self._stack[-1]}")
            return None

        lof = self._istream.tell()  # length offset
        length = Length.decode(self._istream)  # parse length

        vof = self._istream.tell()  # value offset

        self._current = Token(tag, length, TokenOffsets(tof, lof, vof), None, None, None)
        if self._stack:  # 当前层级非顶级，将当前Token加入上级Constructed
            self._current.parent = self._stack[-1]
            self._stack[-1].children.append(self._current)
        else:  # 当前层级为顶级，将当前Token加入self._roots
            self._top_tokens.append(self._current)
        self._on_token_begin()

        if tag.is_primitive:
            self._proceed_primitive()
            self._on_token_end()
            self._accomplish_constructed()
        else:
            self._proceed_constructed()

        return self._current

    def _proceed_primitive(self):
        if not self._current.length.is_definite:  # 不应当是不定长value
            raise InvalidTLV(f"Primitive tag with indefinite length is not supported: {self._current}")

        the_length = self._current.length.value
        value_octets = self._istream.read(the_length)  # value数据字节
        if len(value_octets) < the_length:  # 剩余字节不足
            raise InvalidTLV(f"数据异常截断导致元素不完整/ Incomplete TLV due to data truncation: {self._current}")
        if self._buffer:
            pos = self._current.offsets.v
            end = self._current.offsets.v + self._current.length.value
            self._current.value = memoryview(self._buffer[pos:end])
        else:
            self._current.value = value_octets

    def _proceed_constructed(self):
        self._current.children = []
        self._stack.append(self._current)

    def _accomplish_constructed(self):
        while self._stack:
            # 检查上级元素是否结束
            parent = self._stack[-1]  # 取得上级元素
            if parent.length.is_definite:  # 定长上级元素则计算累计value长度
                expected_pos = parent.offsets.v + parent.length.value
                current_pos = self._istream.tell()  # 当前元素结束时的offset
                if expected_pos == current_pos:  # 相等则上级元素结束，退栈
                    self._current = self._stack.pop()
                    self._on_token_end()
                elif current_pos > expected_pos:  # 当前位置超出上级元素，格式错误
                    raise InvalidTLV(f"当前位置{current_pos}超出上级元素边界{expected_pos}")
                else:  # 表示上级元素内部还继续有子元素
                    break
            else:  # 不定长上级元素
                # 遇到EOC标记结尾，退栈
                if self._current.tag.number == 0 and self._current.length.value == 0:
                    self._current = self._stack.pop()
                    self._on_token_end()
                else:
                    break

    def _on_token_begin(self):
        logger.debug(f'->{"  " * len(self._stack)} {self._current}')
        for obsvr in self._observers:
            obsvr.on_event('begin', self._current, self._stack)

    def _on_token_end(self):
        logger.debug(f'<-{"  " * len(self._stack)} {self._current}')
        for obsvr in self._observers:
            obsvr.on_event('end', self._current, self._stack)


UNIVERSAL_PARSERS = {
    TagNumber.EndOfContent: lambda octets: None,
    TagNumber.Boolean: BooleanValue.decode,
    TagNumber.Integer: lambda octets: int.from_bytes(octets, byteorder='big', signed=True),
    TagNumber.BitString: BitString.decode,
    TagNumber.Null: lambda octets: None,
    TagNumber.ObjectIdentifier: ObjectIdentifier.decode,
    TagNumber.Real: Real.decode,
    TagNumber.Enumerated: lambda octets: int.from_bytes(octets, byteorder='big', signed=True),
    TagNumber.UTCTime: UTCTime.decode,
    TagNumber.GeneralizedTime: GeneralizedTime.decode,
    TagNumber.Time: None,
    TagNumber.DateTime: None,
    TagNumber.Date: None,
    TagNumber.TimeOfDay: None,
    TagNumber.Duration: None
}


for tn in RESTRICTED_STRING_TAGS:
    UNIVERSAL_PARSERS[tn] = partial(RestrictedString.decode, tag_number=tn)


def token_value_to_str(token: Token, parsers: dict = None):
    if token.tag.is_primitive:
        if parsers and token.tag.number in parsers:
            return parsers[token.tag.number].parse(bytes(token.value))

        if token.value is None:
            return 'None'

        if token.tag.cls == TagClass.UNIVERSAL and token.tag.number in UNIVERSAL_PARSERS:
            value_data = UNIVERSAL_PARSERS[token.tag.number](bytes(token.value))
            return 'None' if value_data is None else str(value_data)
        else:
            return 'None' if token.value is None else \
                   f'{token.value[0:3].hex(" ")}...({len(token.value)} bytes)' if len(token.value) > 8 else \
                   token.value.hex(' ')
    else:
        return '[]'


class PrettyPrintObserver(TokenObserver):
    def __init__(self, file=None):
        self._file = file
        print(f'{"T-Off":>8s}{"L-Off":>8s}{"V-Off":>8s}  {"Tag":40s}{"Length":>6s}  {"Value":<s}',
              file=self._file if self._file else sys.stdout)

    """美观打印ASN.1数据的Observer类"""
    def on_event(self, event: str, token: Token, stack: list):
        super().on_event(event, token, stack)
        if event == 'begin' and token.tag.is_primitive:
            return
        if event == 'end' and not token.tag.is_primitive:
            return

        to, lo, vo = token.offsets
        ts = f'{"  " * len(stack)}{str(token.tag)}'
        ls = str(token.length)
        vs = token_value_to_str(token)

        print(f'{to:>8d}{lo:>8d}{vo:>8d}  {ts:40s}{ls:>6s}  {vs:<s}',
              file=self._file if self._file else sys.stdout)

    @staticmethod
    def pretty_print(decoder: Decoder, file=None):
        """通过PrettyPrintObserver类打印ASN.1格式数据"""
        decoder.reset()
        decoder.register_observer(PrettyPrintObserver())

        for _ in iter(decoder):
            pass


class TreeGenerationObserver(TokenObserver):
    def __init__(self):
        self._root = []
        self._stack = [self._root]

    def on_event(self, event: str, token: Token, stack: list):
        super().on_event(event, token, stack)
        if event == 'begin':
            if not token.tag.is_primitive:
                next = []
                self._stack[-1].append((bytes(token.tag.octets), token.length.value, next))
                self._stack.append(next)
        if event == 'end':
            if token.tag.is_primitive:
                self._stack[-1].append((bytes(token.tag.octets), token.length.value, bytes(token.value)))
            else:
                self._stack.pop()

    @staticmethod
    def proceed(decoder: Decoder):
        tg = TreeGenerationObserver()

        decoder.reset()
        decoder.register_observer(tg)
        for _ in iter(decoder):
            pass

        return tg._root



