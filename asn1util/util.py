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


class ASN1EncodingException(Exception):
    def __init__(self, message):
        self.message = message
