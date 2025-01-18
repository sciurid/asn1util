from io import StringIO

from .util import signed_int_to_bytes, unsigned_int_to_bytes
from decimal import Decimal
from typing import Union, Tuple, Optional
import struct
from enum import IntEnum
import logging
import math
from .exceptions import *


logger = logging.getLogger(__name__)

class SpecialRealValue(IntEnum):
    """特殊类型实数的表示类

    X.690 8.5.9 (P9)
    """
    PLUS_INFINITY = 0x40
    """正无穷大"""

    MINUS_INFINITY = 0x41
    """负无穷大"""

    NOT_A_NUMBER = 0x42
    """非实数"""

    MINUS_ZERO = 0x43
    """-0.0"""

    def to_float(self) -> float:
        """转为浮点数"""
        return SPECIAL_REAL_VALUE_CONVERSION[self][0]

    def to_decimal(self) -> Decimal:
        """转为十进制数"""
        return SPECIAL_REAL_VALUE_CONVERSION[self][1]

    @property
    def octets(self) -> bytes:
        return bytes((self.value,))

    @staticmethod
    def eval(byte: int) -> 'SpecialRealValue':
        try:
            return SpecialRealValue(byte)
        except ValueError as ve:
            raise InvalidEncoding(f'Byte value 0x{byte:01x} is not special.')

    @staticmethod
    def from_float(value: float) -> 'SpecialRealValue':
        if math.isinf(value):
            return SpecialRealValue.PLUS_INFINITY if value > 0 else SpecialRealValue.MINUS_INFINITY
        elif math.isnan(value):
            return SpecialRealValue.NOT_A_NUMBER
        elif value == 0.0 and math.copysign(1.0, value) < 0.0:
            return SpecialRealValue.MINUS_ZERO

        raise ValueError(f'Float value {value:f} is not special.')

    @staticmethod
    def from_decimal(dec: Decimal) -> 'SpecialRealValue':
        if dec.is_nan():
            return SpecialRealValue.NOT_A_NUMBER
        elif dec.is_zero():
            if dec.is_signed():
                return SpecialRealValue.MINUS_ZERO
            else:
                raise ValueError("Decimal表示的不是特殊实数")
        elif dec.is_infinite():
            if dec.is_signed():
                return SpecialRealValue.MINUS_INFINITY
            else:
                return SpecialRealValue.PLUS_INFINITY

        raise ValueError(f'Decimal value {dec} is not special.')

    @staticmethod
    def check_special_value(value: Union[float, Decimal]) -> Optional['SpecialRealValue']:
        try:
            if isinstance(value, float):
                sv = SpecialRealValue.from_float(value)
                return sv
            if isinstance(value, Decimal):
                sv = SpecialRealValue.from_decimal(value)
                return sv
        except ValueError:
            return None


SPECIAL_REAL_VALUE_CONVERSION = {
    SpecialRealValue.PLUS_INFINITY: (float('inf'), Decimal('Infinity')),
    SpecialRealValue.MINUS_INFINITY: (float('-inf'), Decimal('-Infinity')),
    SpecialRealValue.NOT_A_NUMBER: (float('nan'), Decimal('Nan')),
    SpecialRealValue.MINUS_ZERO: (-0.0, Decimal('-0'))
}


def decimal_to_base2_sne(value: Decimal, byte_length: int = 8) -> Tuple[int, int, int]:
    """将Decimal类型的十进制数转化为ASN.1格式且以2为底的的S,N,E。

    用于实数Real类型的二进制编码，参见X.690 8.5.7 (P8)。
    注意：通常不应采用base2方式来表示base10的数，会出现精度损失。
    将数值分解为符号项S，整数项N和2的指数项E，并符合DER格式中关于N的最低位不为0的要求。
    :param value: 数值
    :param byte_length: 整数项N的最大字节数（决定了表示的精度）
    :return: (S, N, E) 并且 abs(value) ~= N * pow(2, E)
    """
    logger.warning("Decimal浮点数转二进制表示时方法通常存在精度损失/Possible precision lost in decimal to binary.")
    ds, dd, de = value.as_tuple()  # 将十进制数分解为符号sign、数字digits、指数exponent
    di, df = (dd, None) if de >= 0 else (dd[0:de], dd[de:]) if len(dd) > -de else (None, dd)  # 数字部分分解为整数和小数部分
    fp = Decimal((0, df, de)) if df else Decimal(0)  # 小数部分的十进制表示
    ip = Decimal((0, di, de if de > 0 else 0)) if di else Decimal(0)  # 整数部分的十进制表示

    s: int = ds  # 符号位，1为正，-1为负
    n: int = int(ip.to_integral_exact())  # 整数部分的int表示
    if n.bit_length() > byte_length * 8:  # 整数部分溢出
        raise ValueError(f"数值溢出，实际需要字节数{n.bit_length() // 8 + 1}")
    frac_bits_len = byte_length * 8 - n.bit_length()  # 小数部分的比特数

    for i in range(frac_bits_len):  # 十进制纯小数转化为二进制表示
        fp *= 2  # 纯小数部分乘以2，如果大于1，则在二进制结果中追加1
        n <<= 1  # 整数部分左移1位，空出最低1位追加小数部分二进制结果
        if fp > 1:
            n += 1
            fp -= 1

    e: int = 0 - frac_bits_len  # 二进制的指数等于小数部分bit长度的相反数
    while n & 0x01 == 0:  # X.690 8.5.7.5 CER和DER格式要求n的最低位bit=1
        n >>= 1
        e += 1
    return s, n, e

def int_to_base2_sne(value: int):
    """将int类型的整数转化为ASN.1格式且以2为底的的S,N,E

    用于实数Real类型的二进制编码，参见X.690 8.5.7 (P8)。
    :param value: 待编码的整数
    :return: (S, N, E) 并且 abs(value) == N * pow(2, E)
    """
    s, n = (-1, -value) if value < 0 else (0, value)
    e = 0
    while n & 0x01 == 0:  # X.690 8.5.7.5 CER和DER格式要求n的最低位bit=1
        n >>= 1
        e += 1
    return s, n, e


def ieee754_double_to_base2_sne(float_octets: bytes) -> Union[Tuple[int, int, int], SpecialRealValue]:
    """IEEE 754 双精度浮点数转为S,N,E或者特殊数

    采用IEEE 754浮点数直接转SNE的方式防止精度再次丢失
    :param float_octets: IEEE 754表示双精度数的字节串，big-endian编码
    :return: (S, N, E)并且 abs(value) = N * pow(2, E)或者特殊类型数
    """
    sign = float_octets[0] >> 7
    # 符号位为首个bit
    exp = (((float_octets[0] & 0x7f) << 4) | ((float_octets[1] >> 4) & 0x0f))
    # 指数（exponential）域bit数e = 11
    frac = int.from_bytes(float_octets[2:], byteorder='big', signed=False) + ((float_octets[1] & 0x0f) << 48)
    # 分数（fraction)域转化为整数，共52个比特

    """
    * 来自Wikipedia *
    这里有三个特殊值需要指出：
    如果指数是0并且尾数的小数部分是0，这个数±0（和符号位相关）;    
    如果指数 = {2^{e}-1} 并且尾数的小数部分是0，这个数是±∞（同样和符号位相关）;
    如果指数 = {2^{e}-1} 并且尾数的小数部分非0，这个数表示为非数（NaN）。
    """
    if exp == 0:
        if frac == 0:  # 零
            return (0, 0, 0) if sign == 0 else SpecialRealValue.MINUS_ZERO
        else:  # 次正规数（非规约形式）
            s: int = -1 if sign else 0
            n: int = frac
            # frac是以整数形式表示的小数部分，其中次正规数约定整数部分为0。因此转化为n的时候实际上左移了52位，那么2的指数e应当相应减52。
            e: int = -1074
            # 次正规数的指数偏移值为2 ** (e - 1) - 2 即1022，那么转化为e即为exp - 1022 - 52 = -1074
    elif exp == 0x07ff:  # 无穷大或NaN
        return (SpecialRealValue.MINUS_INFINITY if sign else SpecialRealValue.PLUS_INFINITY) if frac == 0 \
            else SpecialRealValue.NOT_A_NUMBER
    else:  # 正规数（规约形式）
        frac |= 0x10 << 48  # 补上整数部分的1
        s: int = -1 if sign else 0
        n: int = frac
        e: int = exp - 1075
        # IEEE754标准规定指数偏移值是2 ** (e - 1) - 1，即1023，那么转化为e即为exp - 1023 - 52 = -1075

    while n & 0x01 == 0:  # X.690 8.5.7.5 CER和DER格式要求n的最低位bit=1
        n >>= 1
        e += 1
    return s, n, e


def to_binary_encoding(s:int, n: int, e: int, base: int = 2) -> bytes:
    """按照ASN.1 Real格式规范将SNE进行二进制编码

    X.690 8.5.7 (P8)
    :param s: 符号位
    :param n: 尾数mantissa位
    :param e: 指数位
    :param base: 幂底数，取值范围为2、8、16
    :return: 编码后的字节串
    """
    leading: int = 0x80  # b8 = 1，表示二进制（8.5.6）
    #  b7为符号位（8.5.7.1）
    if s != 0:  # b7 = 1 if s = -1 or 0 otherwise
        leading |= 0x40

    #  b6,b5为进制位（8.5.7.2、8.5.7.3）
    f = 0  # 指数的余数
    """
    当base选择8或者16时，以2为底的指数会出现余数的情况，编码中必须将余数保留。
    即 {2^e = 2^{3*e_8+f_8} = 8^e_8 * 2^f_8} 或 {2^e = 2^{4*e_16+f_16} = 16^e_16 * 2^f_16}。
    如 {e = 35} 时，2 ^ 35 = 16 ^ 8 * 2 ^ 3，则存储时选base=16时，e = e //4，f = e % 4。
    """
    if base == 8:  # b6,b5=01，表示八进制
        leading |= 0x10
        e, f = divmod(e, 3)
    elif base == 16:  # b6,b5=10，表示十六进制
        leading |= 0x20
        e, f = divmod(e, 4)
    #  b4,b3为F值用于八进制和六十进制的指数余数
    leading |= (f << 2)  # b4,b3

    data = bytearray()
    #  b2,b1标记指数长度，指数用二进制补码表示（two's complement binary number）（8.5.7.4）
    exp_octets = signed_int_to_bytes(e)
    exp_len = len(exp_octets)

    if exp_len > 255:
        raise UnsupportedValue("指数部分长度{}超过255".format(exp_len))
    elif exp_len < 3:  # 8.5.7.4 b2b1=00/01/02
        leading |= (exp_len - 1) & 0x03
        data.append(leading)
    else:  # 8.5.7.4 b2b1=11 d)
        leading |= 0x03
        data.append(leading)
        data.append(exp_len)
    data.extend(exp_octets)
    data.extend(unsigned_int_to_bytes(n))  # 8.5.7.5
    return bytes(data)


def to_decimal_encoding(value: Union[int, Decimal]) -> bytes:
    """按照ASN.1 Real格式规范将整数int或十进制数Decimal进行十进制编码

    X.690 8.5.8 (P8)
    X.690 11.3.2 (P20)
    注意：通常不应选择用十进制方式保存二进制浮点数，以免出现精度损失情况。如确有需要，可以通过Decimal转换为特定精度。

    :param value: 整数int或者十进制数Decimal
    """
    buffer = StringIO()
    if isinstance(value, int):
        if value < 0:
            buffer.write('-')
            abs_value = -1 * value
        else:
            abs_value = value

        exp = 0
        while abs_value % 10 == 0:
            exp += 1
            abs_value /= 10

        if exp == 0:
            buffer.write('{:d}.E+0'.format(abs_value))
        else:
            buffer.write('{:d}.E{:d}'.format(abs_value, exp))
        return buffer.getvalue().encode('ascii')

    if isinstance(value, Decimal):
        if srv := SpecialRealValue.check_special_value(value):
            return srv.octets
        sign, digits, exponent = value.as_tuple()
        if sign != 0:
            buffer.write('-')

        while digits[-1] == 0:
            exponent += 1
            digits = digits[:-1]

        buffer.write('{:s}.E{:d}'.format(''.join([f'{d:d}' for d in digits]), exponent))
        return b'\x03' + buffer.getvalue().encode('ascii')  # ISO 6093 NR3 form

    raise ValueError("数据{}类型不是int或Decimal".format(value))


def to_ieee758_double(sign: int, number: int, exponent: int) -> float:
    """将数值为s * number * 2 ** exponent的浮点数转化为ieee 758格式"""
    buffer = bytearray()
    el, nl, bias = 11, 52, 1023
    # 指数域的位数、尾数域的位数
    # 指数偏移值 {2 ^ {el - 1} - 1} 2 ** (el - 1) - 1

    """
    尾数每右移1位，指数应当增加1以保持数值不变，若右移完成指数域（指数加偏移值）仍然小于0，则需要用次正规数表示或者向下溢出到0。
    需要将尾数右移至整数部分仅为1，根据相应的指数域判断属于正规数、次正规数、下溢出或上溢出。
    正规数的指数偏移值为{2^(e_bit_len-1)-1}，次正规数的指数偏移值比正规数的小1。          
    """

    n_bit_len = number.bit_length()

    if n_bit_len > nl + 1:
        # 尾数精度超过浮点数规定，按正规数的尾数域长度加整数位数1右移，进行舍弃精度
        r_shift = n_bit_len - nl - 1
        number >>= r_shift
        n_bit_len -= r_shift
        assert n_bit_len == number.bit_length()
        exponent += r_shift  # 对应地增加指数域
        logger.warning("尾数过长造成精度损失{:d}位".format(r_shift))

    r_shift = n_bit_len - 1  # 若正规数可表示（或上溢出），尾数应当右移的位数（除最高位1以外的其他位数）
    exponent_part = exponent + r_shift + bias
    if exponent_part > (1 << el) - 2:
        logger.warning("上溢出")
        return float('-inf') if sign < 0 else float('inf')
    elif exponent_part > 0:  # 正规数可表示（或上溢出）
        significant = (number << (nl - r_shift)) & ((1 << nl) - 1)
        # 有效数（significant）部分等同于尾数（mantissa）左移尾数域位数再右移除最高位1以外的其他位数
    else:  # 次正规数表示或下溢出
        exponent_part = 0
        r_shift = 1 - exponent - bias
        # 要使次正规数的指数域为0的右移位数
        # 注意：次正规数的指数偏移值为bias - 1
        # 即 exponent + bias - 1 + r_shift = 0

        if r_shift > n_bit_len + nl:  # 执行右移以后尾数域将为0
            logger.warning("下溢出")
            return -0.0 if sign < 0 else 0.0
        if nl < r_shift:  # 右移以后发生精度损失
            logger.warning("指数过小造成精度损失{:d}位".format(nl - r_shift))
            significant = number >> (r_shift - nl)
        else:
            significant = number << (nl - r_shift)

    e_bytes = exponent_part.to_bytes(2, byteorder='big', signed=False)
    n_bytes = significant.to_bytes(7, byteorder='big', signed=False)
    buffer.append((0x80 if sign < 0 else 0x00) | ((e_bytes[0] & 0x07) << 3) | ((e_bytes[1] & 0xf0) >> 4))
    buffer.append(((e_bytes[1] & 0x0f) << 4) | (n_bytes[0] & 0x0f))
    buffer.extend(n_bytes[1:])
    return struct.unpack('>d', bytes(buffer))[0]

