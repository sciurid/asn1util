from asn1util import *

from io import BytesIO
from typing import BinaryIO, Generator
import logging

from .datatypes import *


logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)
log_fmt = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
log_console = logging.StreamHandler()
log_console.setFormatter(log_fmt)
logger.addHandler(log_console)


def read_next_tlv(data: Union[bytes, bytearray, BinaryIO], return_octets: bool = True
                  ) -> Tuple[Union[bytes, Tag, None], Union[bytes, Length, None], Optional[bytes]]:
    """从二进制数据或数据流中读取下一个ASN.1 BER

    data: BER-TLV格式的数据流
    return_octets: 返回值格式，True则返回的均为bytes三元组，否则返回(Tag, Length, bytes)三元组
    """
    if isinstance(data, bytes) or isinstance(data, bytearray):
        istream = BytesIO(data)
    else:
        istream = data

    t = Tag.decode(istream)
    if t is None:
        logger.debug('数据为空或读取完毕')
        return None, None, None

    l = Length.decode(istream)
    if l is None:
        raise ASN1Exception(f'Tag存在但Length数据不存在：{t}')
    v = istream.read(l.value)
    if v is None:
        raise ASN1Exception(f'Tag和Length存在但Value数据不存在：{t}({l})')
    elif len(v) < l.value:
        raise ASN1Exception(f'Value数据长度不足：{t}({l}) vs {len(v)}')

    if return_octets:
        return t.octets, l.octets, v
    else:
        return t, l, v


def iter_tlvs(data: Union[bytes, bytearray, BinaryIO], in_octets: bool = True):
    """从二进制数据或数据流中遍历读取ASN.1 BER，不展开constructed元素

    data: BER-TLV格式的数据流
    return_octets: 遍历出的元素格式，True则均为bytes三元组，否则返回(Tag, Length, bytes)三元组
    """
    if isinstance(data, bytes) or isinstance(data, bytearray):
        istream = BytesIO(data)
    else:
        istream = data
    while True:
        t, l, v = read_next_tlv(istream, in_octets)
        if t is None:
            break
        yield t, l, v


def iter_descendant_tlvs(data: Union[bytes, bytearray, BinaryIO], in_octets: bool = True):
    """从二进制数据或数据流中迭代读取ASN.1 BER，按深度优先依次访问constructed元素的子元素

    data: BER-TLV格式的数据流
    return_octets: 遍历出的元素格式，True则均为bytes三元组，否则返回(Tag, Length, bytes)三元组
    """
    if isinstance(data, bytes) or isinstance(data, bytearray):
        istream = BytesIO(data)
    else:
        istream = data

    while True:
        t, l, v = read_next_tlv(istream, False)
        if t is None:
            break
        if in_octets:
            yield t.octets, l.octets, v
        else:
            yield t, l, v
        if not t.is_primitive:
            yield from iter_descendant_tlvs(v, in_octets)

