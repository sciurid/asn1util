import struct
import io
import logging

logger = logging.getLogger(__name__)


def bin_expr(octets: bytes):
    """
    用八位一组的二进制串（01）显示字节串
    :param octets:
    :return:
    """
    return ''.join(map(lambda b: '{:08b}'.format(b), octets))


def signed_int_to_bytes(value: int):
    """
    用最少的字节数表示有符号整数
    :param value: 整数
    :return: 表示整数的字节
    """
    if value == 0:
        return b'\x00'
    elif value > 0:
        min_byte_len = value.bit_length() // 8 + 1
    else:
        abs_bit_len = (-value).bit_length()
        min_byte_len = abs_bit_len // 8 + 1
        # 处理负数补码的边界值，即长度为k字节时可以表示的最小负数为-2**(8k-1)
        if abs_bit_len % 8 == 0 and (0x01 << (abs_bit_len - 1)) + value == 0:
            min_byte_len -= 1

    return value.to_bytes(min_byte_len, byteorder='big', signed=True)


def unsigned_int_to_bytes(value: int):
    """
    用最少的字节数表示无符号整数
    :param value: 非负整数
    :return:
    """
    return value.to_bytes((value.bit_length() + 7) // 8, byteorder='big', signed=False)


def ieee754_double_to_bin_string(value: float) -> str:
    """
    使用二进制串（01）显示双精度浮点数的符号（sign）、指数（exponent）和尾数（mantissa）部分
    :param value:
    :return:
    """
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

