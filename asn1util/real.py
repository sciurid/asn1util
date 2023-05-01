from .tlv import InvalidValue
from .util import *
from decimal import Decimal, Context, getcontext
from typing import Union
import struct
from enum import IntEnum
import logging

logger = logging.getLogger(__name__)


class InvalidReal(InvalidValue):
    def __init__(self, message):
        self.message = message


class SpecialRealValue(IntEnum):
    PLUS_INFINITY = 0x40
    MINUS_INFINITY = 0x41
    NOT_A_NUMBER = 0x42
    MINUS_ZERO = 0x43


class Real:
    PLUS_INFINITY = 0x40
    MINUS_INFINITY = 0x41
    NOT_A_NUMBER = 0x42
    MINUS_ZERO = 0x43
    SPECIALS = (SpecialRealValue.PLUS_INFINITY, SpecialRealValue.MINUS_INFINITY,
                SpecialRealValue.NOT_A_NUMBER, SpecialRealValue.MINUS_ZERO)

    def __init__(self, value: Decimal, special: Union[int, SpecialRealValue] = None):
        self._value = value.normalize()
        self._special = SpecialRealValue(special) if special else None

    def is_special(self):
        return self._special is not None

    def __repr__(self):
        if self._special:
            return self._special.name
        else:
            return str(self._value)

    @property
    def special(self):
        return self._special

    @property
    def value(self):
        return self._value

    @staticmethod
    def eval_float(float_value: float, precision: int = 16):
        return Real(Decimal(float_value, Context(prec=precision)))

    @staticmethod
    def eval_string(string_value: str):
        return Real(Decimal(string_value))

    @staticmethod
    def decompose_decimal_to_sne_of_two(value: Decimal, max_n_octets):
        """
        将数值分解为符号项S，整数项N和2的指数项E，并符合DER格式中关于N的最低位不为0的要求。
        :param value: 数值
        :param max_n_octets: 整数项N的最大字节数（决定了表示的精度）
        :return: (S, N, E) 并且 abs(value) = N * pow(2, E)
        """
        value = value.normalize()
        if value == 0:
            return 0, 0, 0
        s = -1 if value < 0 else 0
        abs_value = abs(value)
        n = int(abs_value)
        frac_part = abs_value - n

        frac_bit_len = max_n_octets * 8 - n.bit_length()
        for i in range(frac_bit_len):
            frac_part *= 2
            if frac_part < 1:
                n <<= 1
            else:
                n = (n << 1) + 1
                frac_part -= 1
        e = -1 * frac_bit_len
        while n & 0x01 == 0:
            n >>= 1
            e += 1
        return s, n, e

    @staticmethod
    def decompose_int_to_sne_of_two(value: int):
        s = -1 if value < 0 else 0
        n = abs(value)
        e = 0
        return s, n, e

    @staticmethod
    def decompose_ieee754_double(encoded: bytes) -> (int, int, int):
        sign = encoded[0] >> 7
        exp = (((encoded[0] & 0x7f) << 4) | ((encoded[1] >> 4) & 0x0f))
        fraction = int.from_bytes(encoded[2:], byteorder='big', signed=False) + ((encoded[1] & 0x0f) << 48)
        if exp == 0:  # 零或次正规数
            if fraction == 0:
                if sign == 0:
                    return 0, 0, 0
                else:
                    raise SpecialRealValue.MINUS_ZERO
            else:
                return (-1 if sign else 0), fraction, -1074  # 小数部分左移52位成为整数，次正规数的指数-1022再减52
        elif exp == 0x07ff:  # 无穷大或NaN
            if fraction:
                raise SpecialRealValue.NOT_A_NUMBER
            else:
                raise SpecialRealValue.MINUS_INFINITY if sign else SpecialRealValue.PLUS_INFINITY
        else:
            fraction |= 0x10 << 48  # 补上整数部分的1
            return (-1 if sign else 0), fraction, exp - 1075  # 小数部分左移52位成为整数，正规数的指数减去1023再减52

    @staticmethod
    def decompose_ieee754_single(encoded: bytes) -> (int, int, int):
        sign = encoded[0] >> 7
        exp = (((encoded[0] & 0x7f) << 1) | ((encoded[1] >> 7) & 0x01))
        fraction = int.from_bytes(encoded[2:], byteorder='big', signed=False) + ((encoded[1] & 0x7f) << 16)
        if exp == 0:  # 零或次正规数
            if fraction == 0:
                if sign == 0:
                    return 0, 0, 0
                else:
                    raise SpecialRealValue.MINUS_ZERO
            else:
                return (-1 if sign else 0), fraction, -149  # 小数部分左移52位成为整数，次正规数的指数-126再减23
        elif exp == 0xff:  # 无穷大或NaN
            if fraction:
                raise SpecialRealValue.NOT_A_NUMBER
            else:
                raise SpecialRealValue.MINUS_INFINITY if sign else SpecialRealValue.PLUS_INFINITY
        else:
            fraction |= 0x80 << 16  # 补上整数部分的1
            return (-1 if sign else 0), fraction, exp - 150   # 小数部分左移52位成为整数，正规数的指数减去127再减23

    @staticmethod
    def decompose_float_to_sne_of_two(value: float, double: bool = True):
        if value == 0:
            return 0, 0, 0

        if double:
            s, n, e = Real.decompose_ieee754_double(struct.pack('>d', value))
        else:
            s, n, e = Real.decompose_ieee754_single(struct.pack('>f', value))
        assert (s == -1) if value < 0 else (s == 0)

        while n & 0x01 == 0:
            n >>= 1
            e += 1
        return s, n, e

    @staticmethod
    def encode_base2(value: Union[Decimal, float, int], base: int = 2, max_n_octets: int = 4) -> bytes:
        """按照ASN.1实数二进制格式编码浮点数（ITU-T X.690 8.5）
        """
        assert base in (2, 8, 16)
        data = bytearray()
        first_octet = 0x80  # b8 = 1，表示二进制（8.5.6）
        if type(value) == float:
            s, n, e = Real.decompose_float_to_sne_of_two(value)
        elif type(value) == int:
            s, n, e = Real.decompose_int_to_sne_of_two(value)
        else:
            s, n, e = Real.decompose_decimal_to_sne_of_two(value, max_n_octets)

        logger.debug(f'{value} => {s}, {n}, {e}')

        #  b7为符号位（8.5.7.1）
        if s != 0:  # b7 = 1 if s = -1 or 0 otherwise
            first_octet |= 0x40

        #  b6,b5为进制位（8.5.7.2、8.5.7.3）
        f = 0
        if base == 8:  # b6,b5=01，表示八进制
            first_octet |= 0x10
            f = e % 3
            e = e // 3
        elif base == 16:  # b6,b5=10，表示十六进制
            first_octet |= 0x20
            f = e % 4
            e = e // 4
        #  b4,b3为F值用于八进制和六十进制的指数余数
        first_octet |= (f << 2)  # b4,b3

        #  b2,b1标记指数长度，指数用二进制补码表示（two's complement binary number）（8.5.7.4）
        exp_octets = signed_int_to_bytes(e)
        exp_len = len(exp_octets)

        if exp_len == 1:  # 长度为1
            data.append(first_octet)
            pass  # b2,b1=00
        elif exp_len == 2:  # 长度为2
            first_octet |= 0x01  # b2,b1=01
            data.append(first_octet)
        elif exp_len == 3:  # 长度为3
            first_octet |= 0x02  # b2,b1=10
            data.append(first_octet)
        else:  # 长度超过3，下一个字节为长度值（无符号）
            first_octet |= 0x03  # b2,b1=11
            data.append(first_octet)
            data.extend(unsigned_int_to_bytes(exp_len))
        data.extend(exp_octets)
        data.extend(unsigned_int_to_bytes(n))  # 8.5.7.5
        return data

    @staticmethod
    def encode_base10(value: Union[int, float, Decimal], nr: int = 2) -> bytes:
        assert nr in (1, 2, 3)
        str_value = None
        first_octet = None
        if nr == 1:
            first_octet = b'\x01'
            str_value = f'{int(value):d}'
        elif nr == 2:
            first_octet = b'\x02'
            if type(value) == int:
                str_value = f'{value:d}'
            elif type(value) == float:
                str_value = f'{value:.15g}'.rstrip('0')
            elif type(value) == Decimal:
                str_value = str(value)
        elif nr == 3:
            first_octet = b'\x03'
            str_value = f'{value:e}'

        return first_octet + str_value.encode('ascii')

    @staticmethod
    def encode(value, base: int = 10, nr: int = 2, max_n_octets: int = 4):
        if base == 10:
            return Real.encode_base10(value, nr)
        elif base in (2, 8, 16):
            return Real.encode_base2(value, base, max_n_octets)
        else:
            raise InvalidReal('Base should be 2, 8, 16 or 10.')

    @staticmethod
    def _decode_base2(octets: bytes):
        fo = octets[0]  # for short of first_octet
        assert fo & 0x80 != 0
        s = 1 if (fo & 0x40) == 0 else -1  # b7 -> sign
        b = (2, 8, 16, None)[(fo >> 4) & 0x03]  #b6,b5 -> base
        if b is None:
            raise InvalidReal("Base is a reserved value. (b6,b5=11")
        f = fo >> 2 & 0x03
        le = fo & 0x03
        if le == 0 or le == 1 or le == 2:
            assert len(octets) > le + 2
            eo = octets[1:le+2]
            no = octets[le+2:]
        else:
            lle = octets[1]
            assert len(octets) > lle + 3
            eo = octets[2:lle+2]
            no = octets[lle+2:]
        e = int.from_bytes(eo, byteorder='big', signed=True)
        n = int.from_bytes(no, byteorder='big', signed=False)
        ctx = getcontext()
        dec_val = Decimal(n) * ctx.power(b, e) * ctx.power(2, f) * s
        return Real(dec_val)

    @staticmethod
    def _decode_base10(octets: bytes):
        assert octets[0] & 0xC0 == 0
        nr = octets[0] & 0x3f
        if nr == 0x01 or nr == 0x02 or nr == 0x03:  # nr1, nr2, nr3
            return Real.eval_string(octets[1:].decode('ascii'))
        else:
            raise InvalidReal("Decimal encoding is specified but not a valid representation is chosen.")

    @staticmethod
    def decode(octets: bytes):  # 8.5.6
        assert len(octets) > 0
        fo = octets[0]  # for short of first_octet
        if fo & 0x80 != 0:  # b8=1
            return Real._decode_base2(octets)
        elif fo & 0x40 == 0:  # b8,b7=00
            return Real._decode_base10(octets)
        elif fo in Real.SPECIALS:
            if len(octets) != 1:
                raise InvalidReal("Special real value with following octets")
            return Real(value=Decimal(), special=fo)
        else:
            raise InvalidReal("Not a valid binary, decimal or special value representation.")