from .tlv import *
from .encoding import *
from collections import namedtuple
from io import BytesIO


DecoderStackItem = namedtuple('DecoderStackItem', ['tag', 'length', 'value_offset'])
TLVOffsets = namedtuple('TLVOffsets', ['t', 'l', 'v'])


def dfs_decoder(data: BinaryIO):
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
            yield tag, length, value_octets, offsets, stack  # 返回基本类型

            if len(stack) == 0:  # 根元素
                continue

            # 检查上级元素是否结束
            parent = stack[-1]  # 取得上级元素
            if parent.length.is_definite:  # 定长上级元素则计算累计value长度
                cur_pos = data.tell()  # 当前元素结束时的offset
                exp_pos = parent.value_offset + parent.length.value  # 上级元素结束时的offset
                if cur_pos == exp_pos:  # 相等则上级元素结束，退栈
                    stack.pop()
                elif cur_pos > exp_pos:  # 当前位置超出上级元素结束值，格式错误
                    raise InvalidTLV(f"Length of sub-tlvs in value {cur_pos - parent.value_offset} "
                                     f"exceeds the specified length {parent.length.value}.")
            else:  # 不定长上级元素
                if tag.number == 0 and length.value == 0:  # 遇到EOC标记结尾，退栈
                    stack.pop()
        else:
            yield tag, length, None, offsets, stack  # 返回结构类型
            stack.append(DecoderStackItem(tag, length, vof))


def decode_print(data):
    for tag, length, value_octets, offsets, stack in dfs_decoder(BytesIO(data)):
        indent = ' ' * 2 * len(stack)
        print(f'{indent} {tag} {length} [V]{"" if value_octets is None else value_octets.hex(" ")}')
