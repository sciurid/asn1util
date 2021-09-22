from .tlv import *
from .encoding import *
from .oid import *
from .real import *

from collections import namedtuple


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

            while len(stack) > 0:
                # 检查上级元素是否结束
                parent = stack[-1]  # 取得上级元素
                if parent.length.is_definite:  # 定长上级元素则计算累计value长度
                    cur_pos = data.tell()  # 当前元素结束时的offset
                    exp_pos = parent.value_offset + parent.length.value  # 上级元素结束时的offset
                    if cur_pos == exp_pos:  # 相等则上级元素结束，退栈
                        stack.pop()
                        continue
                    elif cur_pos > exp_pos:  # 当前位置超出上级元素结束值，格式错误
                        raise InvalidTLV(f"Length of sub-tlvs in value {cur_pos - parent.value_offset} "
                                         f"exceeds the specified length {parent.length.value}.")
                    else:
                        break
                else:  # 不定长上级元素
                    if tag.number == 0 and length.value == 0:  # 遇到EOC标记结尾，退栈
                        stack.pop()
                        continue
        else:
            yield tag, length, None, offsets, stack  # 返回结构类型
            stack.append(DecoderStackItem(tag, length, vof))


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
    TagNumber.Time: lambda value: datetime.fromisoformat(value.decode('ascii')),
    TagNumber.DateTime: lambda value: datetime.fromisoformat(value.decode('ascii')),
    TagNumber.Date: lambda value: date.fromisoformat(value.decode('ascii')),
    TagNumber.TimeOfDay: lambda value: time.fromisoformat(value.decode('ascii')),
    TagNumber.Duration: lambda value: decode_duration(value)
}


def decode_print(file):
    for tag, length, value_octets, offsets, stack in dfs_decoder(file):
        indent = ' ' * 2 * len(stack)
        if tag.is_primitive:
            if tag.number in VALUE_TYPE_DECODERS:
                handler = VALUE_TYPE_DECODERS[tag.number]
                value_data = handler(value_octets)
                value_string = 'N/A' if value_data is None else str(value_data)
            else:
                value_string = 'N/A' if value_octets is None else value_octets.hex(' ')
        else:
            value_string = ''
        print(f'{offsets.t:<8d}{offsets.l:<8d}{offsets.v:<8d}{indent+str(tag):40s}{length.value:<6d}{value_string:<s}')
