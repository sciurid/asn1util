from .tlv import *
from .encoding import *
from .oid import *
from .real import *

from collections import namedtuple


DecoderStackItem = namedtuple('DecoderStackItem', ['tag', 'length', 'offsets'])
TLVOffsets = namedtuple('TLVOffsets', ['t', 'l', 'v'])
TLVItem = namedtuple('TLVItem', ['tag', 'length', 'value_octets', 'offsets', 'stack', 'decoded_value', 'tlv_octets'])


def dfs_decoder(data: BinaryIO, constructed_end_handler=None):
    """
    TLV生成器，按照DER编码顺序逐个解析TLV，即深度优先遍历（DFS）。
    解析到原始类型TLV，则在TLV结束后返回TLVItem。
    解析到结构类型TLV，则则TLV的T、L结束后返回TLVItem；继续执行时开始解析结构内的TLV。
    :param data: 二进制流
    :param constructed_end_handler: 结构类型TLV结束解析时的处理函数，参数为TLVItem。
    :return:
    """
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
            if tag.number in VALUE_TYPE_DECODERS:
                handler = VALUE_TYPE_DECODERS[tag.number]
                decoded_value = handler(value_octets)
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
            yield TLVItem(tag, length, None, offsets, stack, None, None)  # 返回结构类型
            stack.append(DecoderStackItem(tag, length, TLVOffsets(tof, lof, vof)))


VALUE_TYPE_DECODERS = {
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


def decode_print(file):
    for tlvitem in dfs_decoder(file):
        indent = ' ' * 2 * len(tlvitem.stack)
        if tlvitem.tag.is_primitive:
            if tlvitem.tag.number in VALUE_TYPE_DECODERS:
                handler = VALUE_TYPE_DECODERS[tlvitem.tag.number]
                value_data = handler(tlvitem.value_octets)
                value_string = 'N/A' if value_data is None else str(value_data)
            else:
                value_string = 'N/A' if tlvitem.value_octets is None else tlvitem.value_octets.hex(' ')
        else:
            value_string = ''
        print(f'{tlvitem.offsets.t:<8d}{tlvitem.offsets.l:<8d}{tlvitem.offsets.v:<8d}'
              f'{indent+str(tlvitem.tag):40s}{tlvitem.length.value:<6d}{value_string:<s}')
        # print(f'{tlvitem.tlv_octets.hex(" ")}' if tlvitem.tlv_octets is not None else '')
