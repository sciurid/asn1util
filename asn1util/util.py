import struct
import io
import logging

logger = logging.getLogger(__name__)


def bin_expr(octets: bytes):
    return ''.join(map(lambda b: '{:08b}'.format(b), octets))


def repr_bit_string(octets: bytes, bit_length: int):
    return bin_expr(octets)[0:bit_length]


__BOUNDARIES = [2 ** (n * 8 + 7) * (-1) for n in range(8)]


def signed_int_to_bytes(value: int):
    """
    用最少的字节数表示有符号整数
    :param value: 整数
    :return:
    """
    for i, v in enumerate(__BOUNDARIES):  # 处理8字节以内的边界负数
        if value == v:
            return b'\x80' + i * b'\x00'

    est_octet_len = value.bit_length() // 8 + 1
    encoded = value.to_bytes(est_octet_len, byteorder='big', signed=True)
    if est_octet_len > 8 and encoded[0] == 0xff and encoded[1] & 0x80 != 0:  # 处理8字节以上的边界负数
        return encoded[1:]
    else:
        return encoded


def unsigned_int_to_bytes(value: int):
    """
    用最少的字节数表示无符号整数
    :param value: 非负整数
    :return:
    """
    return value.to_bytes((value.bit_length() + 7) // 8, byteorder='big', signed=False)


def ieee754_double_to_bin_string(value: float) -> str:
    ref = struct.pack(">d", value)
    info = io.StringIO()
    info.write(f'{ref[0] >> 7:1b} ')
    info.write(f'{ref[0] & 0x7f:07b} ')
    info.write(f'{ref[1] >> 4:04b} ')
    info.write(f'{ref[1] & 0x0f:04b} ')
    for i in range(2, 8):
        info.write(f'{ref[i]:08b} ')

    logger.debug(f'{ref.hex(" ")}: {info.getvalue()}')
    return info.getvalue()

