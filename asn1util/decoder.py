from .tlv import *
from .encoding import *
from .oid import *
from .real import *

from collections import namedtuple
from collections.abc import Iterator
from dataclasses import dataclass
from io import BytesIO
from typing import NamedTuple
import logging

logger = logging.getLogger(__name__)


DecoderStackItem = namedtuple('DecoderStackItem', ['tag', 'length', 'offsets'])
TLVOffsets = namedtuple('TLVOffsets', ['t', 'l', 'v'])
TLVItem = namedtuple('TLVItem', ['tag', 'length', 'value_octets', 'offsets', 'stack', 'decoded_value', 'tlv_octets'])


TokenOffsets = NamedTuple('TokenOffsets', t=int, l=int, v=int)

@dataclass
class Token:
    tag: Tag
    length: Length
    offsets: TokenOffsets
    value: bytes



def default_begin_handler(token: Token):
    logger.debug(f'--->{token}')

def default_end_handler(token: Token):
    logger.debug(f'<---{token}')

class Decoder(Iterator):
    def __init__(self, data: Union[bytes, BinaryIO]):
        super().__init__()
        self._buffer = BytesIO(data) if isinstance(data, bytes) else data
        self._stack = []
        self._current = None


    def proceed_token(self, begin_handler=default_begin_handler, end_handler=default_end_handler):
        tof = self._buffer.tell()  # tag offset
        tag = Tag.decode(self._buffer)  # parse tag
        if tag is None:  # EOF of data
            return None

        lof = self._buffer.tell()  # length offset
        length = Length.decode(self._buffer)  # parse length

        vof = self._buffer.tell()  # value offset

        self._current = Token(tag, length, TokenOffsets(tof, lof, vof), None)
        if begin_handler:
            begin_handler(self._current)

        if tag.is_primitive:
            self._proceed_primitive()
            if end_handler:
                end_handler(self._current)
            self._accomplish_constructed(end_handler)
        else:
            self._proceed_constructed()

        return self._current

    def _proceed_primitive(self):
        if not self._current.length.is_definite:  # 不应当是不定长value
            raise InvalidTLV(f"Primitive tag '{tag}' with indefinite length is not supported.")

        l = self._current.length.value
        value_octets = self._buffer.read(l)  # value数据字节
        if len(value_octets) < l:  # 剩余字节不足
            raise InvalidTLV(f"Not enough value octets. {l:d} required but {len(value_octets):d} remains.")
        self._current.value = value_octets

    def _proceed_constructed(self):
        self._stack.append(self._current)

    def _accomplish_constructed(self, end_handler=None):
        while self._stack:
            # 检查上级元素是否结束
            parent = self._stack[-1]  # 取得上级元素
            if parent.length.is_definite:  # 定长上级元素则计算累计value长度
                expected_pos = parent.offsets.v + parent.length.value
                current_pos = self._buffer.tell()  # 当前元素结束时的offset
                if expected_pos == current_pos:  # 相等则上级元素结束，退栈
                    last = self._stack.pop()
                    if end_handler:
                        end_handler(last)
                elif current_pos > expected_pos:  # 当前位置超出上级元素结束值，格式错误
                    raise InvalidTLV(f"当前位置{current_pos}超出上级元素结束值{expected_pos}")
                else:  # 表示上级元素内部还继续有子元素
                    break
            else:  # 不定长上级元素
                # 遇到EOC标记结尾，退栈
                if self._current.tag.number == 0 and self._current.length.value == 0:
                    last = self._stack.pop()
                    if end_handler:
                        end_handler(last)
                else:
                    break

    def __next__(self):
        token = self.proceed_token()
        if token:
            return token
        else:
            raise StopIteration




def dfs_decoder(data: Union[bytes, BinaryIO], constructed_end_handler=None):
    """
    TLV生成器，按照DER编码顺序逐个解析TLV，即深度优先遍历（DFS）。
    解析到原始类型TLV，则在TLV结束后返回TLVItem。
    解析到结构类型TLV，则在TLV的T、L结束后返回TLVItem；继续执行时开始解析结构内的TLV。
    :param data: 二进制流
    :param constructed_end_handler: 结构类型TLV结束解析时的处理函数，参数为TLVItem。
    :return:
    """
    if isinstance(data, bytes):
        data = BytesIO(data)
    stack = []  # 标记当前结构路径的栈
    while True:
        tof = data.tell()  # tag offset
        tag = Tag.decode(data)  # parse tag
        if tag is None:  # EOF of data
            break

        lof = data.tell()  # length offset
        length = Length.decode(data)  # parse length

        vof = data.tell()  # value offset
        offsets = TLVOffsets(tof, lof, vof)

        if tag.is_primitive:  # 基本类型
            if not length.is_definite:  # 不应当是不定长value
                raise InvalidTLV(f"Primitive tag '{tag}' with indefinite length is not supported.")
            value_octets = data.read(length.value)  # value数据字节
            if len(value_octets) < length.value:  # 剩余字节不足
                raise InvalidTLV(f"Not enough value octets. {length.value:d} required but {len(value_octets):d} remains.")
            if tag.number in UNIVERSAL_DECODERS:
                handler = UNIVERSAL_DECODERS[tag.number]
                decoded_value = handler(value_octets)
            else:
                decoded_value = None
            tlv_end_offset = data.tell()
            data.seek(tof)
            # 返回基本类型
            yield TLVItem(tag, length, value_octets, offsets, stack, decoded_value, data.read(tlv_end_offset - tof))

            if len(stack) == 0:  # 根元素
                continue

            while len(stack) > 0:
                # 检查上级元素是否结束
                parent = stack[-1]  # 取得上级元素
                if parent.length.is_definite:  # 定长上级元素则计算累计value长度
                    cur_pos = data.tell()  # 当前元素结束时的offset
                    pof = parent.offsets
                    exp_pos = pof.v + parent.length.value  # 上级元素结束时的offset
                    if cur_pos == exp_pos:  # 相等则上级元素结束，退栈
                        stack.pop()
                        if constructed_end_handler is not None:  # 如果有结构类型TLV完成处理函数，则调用
                            data.seek(pof.t)
                            tlv_octets = data.read(cur_pos - pof.t)
                            constructed_item = \
                                TLVItem(parent.tag, parent.length, tlv_octets[(pof.v - pof.t):],
                                        offsets, stack, None, tlv_octets)
                            constructed_end_handler(constructed_item)
                        continue
                    elif cur_pos > exp_pos:  # 当前位置超出上级元素结束值，格式错误
                        raise InvalidTLV(f"Length of sub-tlvs in value {cur_pos - pof.v} "
                                         f"exceeds the specified length {parent.length.value}.")
                    else:
                        break
                else:  # 不定长上级元素
                    if tag.number == 0 and length.value == 0:  # 遇到EOC标记结尾，退栈
                        stack.pop()
                        continue
                    else:
                        break
        else:
            yield TLVItem(tag, length, None, offsets, stack, None, None)  # 返回结构类型
            stack.append(DecoderStackItem(tag, length, TLVOffsets(tof, lof, vof)))


UNIVERSAL_DECODERS = {
    TagNumber.EndOfContent: lambda value: None,
    TagNumber.Boolean: BooleanValue.decode,
    TagNumber.Integer: lambda value: int.from_bytes(value, byteorder='big', signed=True),
    TagNumber.BitString: BitString.decode,
    TagNumber.Null: lambda value: None,
    TagNumber.ObjectIdentifier: ObjectIdentifier.decode,
    TagNumber.Real: Real.decode,
    TagNumber.Enumerated: lambda value: int.from_bytes(value, byteorder='big', signed=True),
    TagNumber.UTF8String: lambda value: value.decode('utf-8'),
    TagNumber.UniversalString: lambda value: value.decode("utf-32"),
    TagNumber.BMPString: lambda value: value.decode('utf-16'),
    TagNumber.PrintableString: decode_restricted_string,
    TagNumber.NumericString: decode_restricted_string,
    TagNumber.T61String: decode_restricted_string,
    TagNumber.IA5String: decode_restricted_string,
    TagNumber.UTCTime: UTCTime.decode,
    TagNumber.GeneralizedTime: GeneralizedTime.decode,
    TagNumber.Time: None,
    TagNumber.DateTime: None,
    TagNumber.Date: None,
    TagNumber.TimeOfDay: None,
    TagNumber.Duration: None
}


def decode_print(file, tag_names: dict = None):
    for tlvitem in dfs_decoder(file):
        indent = ' ' * 2 * len(tlvitem.stack)
        if tlvitem.tag.is_primitive:
            if tlvitem.tag.cls == TagClass.UNIVERSAL and tlvitem.tag.number in UNIVERSAL_DECODERS:
                handler = UNIVERSAL_DECODERS[tlvitem.tag.number]
                value_data = handler(tlvitem.value_octets)
                value_string = 'N/A' if value_data is None else str(value_data)
            else:
                value_string = 'N/A' if tlvitem.value_octets is None else tlvitem.value_octets.hex(' ')
        else:
            value_string = ''

        print(f'{tlvitem.offsets.t:<8d}{tlvitem.offsets.l:<8d}{tlvitem.offsets.v:<8d}'
              f'{indent+str(tlvitem.tag):40s}{str(tlvitem.length.value) if tlvitem.length.is_definite else "INF":<6s}'
              f'{value_string:<s}')
        if tag_names:
            if tlvitem.tag.value in tag_names:
                print(' ' * 24 + indent + tag_names[tlvitem.tag.value])
            else:
                print(' ' * 24 + indent + '[UNKNOWN]')

        # print(f'{tlvitem.tlv_octets.hex(" ")}' if tlvitem.tlv_octets is not None else '')
