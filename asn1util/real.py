import io

from .tlv import InvalidValue
from .util import *
from decimal import Decimal, Context, getcontext
from typing import Union
import struct
from enum import IntEnum
import logging
from types import MappingProxyType
import math

logger = logging.getLogger(__name__)


class InvalidReal(InvalidValue):
    def __init__(self, message):
        super().__init__(message)


class InvalidSpecialRealValue(InvalidValue):
    def __init__(self, message):
        super().__init__(message)


class SpecialRealValue(IntEnum):
    PLUS_INFINITY = 0x40
    MINUS_INFINITY = 0x41
    NOT_A_NUMBER = 0x42
    MINUS_ZERO = 0x43

    def to_float(self) -> bytes:
        if self == SpecialRealValue.PLUS_INFINITY:
            return float('inf')
        elif self == SpecialRealValue.MINUS_INFINITY:
            return float('-inf')
        elif self == SpecialRealValue.NOT_A_NUMBER:
            return float('nan')
        elif self == SpecialRealValue.MINUS_ZERO:
            return -0.0

    def to_octet(self):
        return _SPECIAL_REAL_VALUE_OCTETS[self]

    def to_decimal(self):
        if self == SpecialRealValue.PLUS_INFINITY:
            return Decimal('Infinity')
        elif self == SpecialRealValue.MINUS_INFINITY:
            return Decimal('-Infinity')
        elif self == SpecialRealValue.NOT_A_NUMBER:
            return Decimal('Nan')
        elif self == SpecialRealValue.MINUS_ZERO:
            return Decimal('-0')


    @staticmethod
    def from_float(value: float):
        if math.isinf(value):
            return SpecialRealValue.PLUS_INFINITY if value > 0 else SpecialRealValue.MINUS_INFINITY
        elif math.isnan(value):
            return SpecialRealValue.NOT_A_NUMBER
        elif value == 0.0 and math.copysign(1.0, value) < 0.0:
            return SpecialRealValue.MINUS_ZERO

        raise InvalidSpecialRealValue(f'Float value {value:f} is not special.')

    @staticmethod
    def from_octet(b: int):
        if b in _SPECIAL_REAL_VALUE_ENUMS:
            return _SPECIAL_REAL_VALUE_ENUMS[b]

        raise InvalidSpecialRealValue(f'Byte value 0x{b:01x} is not special.')

    @staticmethod
    def from_decimal(dec: Decimal):
        if dec.is_nan():
            return SpecialRealValue.NOT_A_NUMBER
        elif dec.is_zero():
            if dec.is_signed():
                return SpecialRealValue.MINUS_ZERO
            else:
                return '0.E+0'
        elif dec.is_infinite():
            if dec.is_signed():
                return SpecialRealValue.MINUS_INFINITY
            else:
                return SpecialRealValue.PLUS_INFINITY

        raise InvalidSpecialRealValue(f'Decimal value 0x{dec:d} is not special.')


_SPECIAL_REAL_VALUE_OCTETS = MappingProxyType({
    s: s.to_bytes(1, byteorder='big', signed=False) for s in SpecialRealValue})
_SPECIAL_REAL_VALUE_ENUMS = MappingProxyType({int(s): s for s in SpecialRealValue})


class Real:
    def __init__(self, value: Union[float, int, Decimal, SpecialRealValue, bytes]):
        if isinstance(value, SpecialRealValue):
            self._value = value
            self._octets = value.to_octet()
        elif isinstance(value, float):
            self._value = value
            self._octets = Real.encode_float(value)
        elif isinstance(value, int) or isinstance(value, Decimal):
            self._value = value
            self._octets = Real.encode_decimal(value)
        elif isinstance(value, bytes):
            self._octets = value
            self._value = Real.decode(value)
        else:
            raise InvalidReal(f'Value {value} of type {type(value)} is not supported')

    @staticmethod
    def decompose_decimal_to_sne_of_two(value: Decimal, max_bytes: int = 8):
        """
        注意：不应采用base2方式来表示base10的数值，会出现精度损失。
        将数值分解为符号项S，整数项N和2的指数项E，并符合DER格式中关于N的最低位不为0的要求。
        :param value: 数值
        :param max_bytes: 整数项N的最大字节数（决定了表示的精度）
        :return: (S, N, E) 并且 abs(value) = N * pow(2, E)
        """
        logger.warning("此方法通常存在精度损失，通常不应调用/ This methods may result in precision lost.")
        ds, dd, de = value.as_tuple()
        di, df = (dd, ()) if de >= 0 else (dd[0:de], dd[de:]) if len(dd) > -de else ((), dd)
        fp = Decimal((0, df, de)) if df else Decimal(0)
        ip = Decimal((0, di, de if de > 0 else 0)) if di else Decimal(0)

        s = ds
        n = int(ip.to_integral_exact())
        remainder = max_bytes * 8 - n.bit_length()  # 默认达到双精度数的精度
        if remainder <= 0:  # 整数部分即溢出
            n >>= (-1 * remainder)
            e = 0 - remainder
            logger.warning(f'Integral part of decimal value {value} exceeds the max_bytes {max_bytes} limit.')
            return s, n, e

        for i in range(remainder):
            fp *= 2
            if fp < 1:
                n <<= 1
            else:
                n = (n << 1) + 1
                fp -= 1
        e = 0 - remainder
        while n & 0x01 == 0:
            n >>= 1
            e += 1
        return s, n, e

    @staticmethod
    def decompose_int_to_sne_of_two(value: int):
        s = -1 if value < 0 else 0
        n = abs(value)
        e = 0
        while n & 0x01 == 0:
            n >>= 1
            e += 1
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
    def encode_float(value: Union[float, int], base: int = 2, double: bool = True) -> Union[bytes, SpecialRealValue]:
        """按照ASN.1实数二进制格式编码浮点数（ITU-T X.690 8.5）
        base: 用于CER和DER时必须为2
        """
        try:
            return SpecialRealValue.from_float(value).to_octet()
        except InvalidSpecialRealValue:
            pass

        if type(value) == float:
            if double:
                s, n, e = Real.decompose_float_to_sne_of_two(value)
            else:
                s, n, e = Real.decompose_float_to_sne_of_two(value, False)
        elif type(value) == int:
            s, n, e = Real.decompose_int_to_sne_of_two(value)

        logger.debug(f'{value} => {s}, {n}, {e}')
        return Real._encode_sne_base2(s, n, e, base)

    @staticmethod
    def _encode_sne_base2(s: int, n: int, e: int, base: int = 2):
        assert base in (2, 8, 16)
        assert s in (-1, 0)

        data = bytearray()
        first_octet = 0x80  # b8 = 1，表示二进制（8.5.6）
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
    def encode_decimal(value: Union[int, Decimal], nr: int = 3) -> bytes:
        assert nr in (1, 2, 3)
        if isinstance(value, Decimal):
            try:
                return SpecialRealValue.from_decimal(value).to_octet()
            except InvalidSpecialRealValue:
                pass
            dec = value
        elif isinstance(value, int):
            dec = Decimal(value)
        else:
            raise InvalidReal("十进制编码仅接受int和Decimal类型/ Only int and Decimal is accepted for base10 encoding.")

        first_octet = None
        str_value = None

        s, d, e = dec.as_tuple()
        if nr == 1:
            first_octet = b'\x01'
            if e < 0:
                raise InvalidReal('无法用NR1格式表示小数/ NR1 form is not eligible for fractional parts')
            str_value = f'{int(dec):d}'
        elif nr == 2:
            first_octet = b'\x02'
            str_value = f'{dec:f}'
        elif nr == 3:
            first_octet = b'\x03'
            l, r = 0, 0
            while d[l] == 0:
                l += 1
            while d[r] == 0:
                r += 1
            if r > 0:
                d = d[l:0 - r]
                e += r
            str_value = f'{"-" if s else ""}{"".join([str(d) for d in d])}.E{e:d}'

        return first_octet + str_value.encode('ascii')

    @staticmethod
    def encode(value: Union[int, float, Decimal]):
        if isinstance(value, int) or isinstance(value, Decimal):
            return Real.encode_decimal(value)
        elif isinstance(value, float):
            return Real.encode_float(value)
        else:
            raise InvalidReal('实数类型只接受int、float、Decimal类型/ Only int, float and Decimal is supported.')

    @staticmethod
    def _decode_base2s(octets: bytes) -> Union[float, Decimal]:
        logger.debug(f'{octets.hex(" ")}')
        fo = octets[0]  # for short of first_octet
        assert fo & 0x80 != 0
        s = 1 if (fo & 0x40) == 0 else -1  # b7 -> sign
        b = (2, 8, 16, None)[(fo >> 4) & 0x03]  # b6,b5 -> base
        if b is None:
            raise InvalidReal("Base is a reserved value. (b6,b5=11")
        f = fo >> 2 & 0x03
        le = fo & 0x03
        if le == 0 or le == 1 or le == 2:
            assert len(octets) > le + 1
            eo = octets[1:le+2]
            no = octets[le+2:]
        else:
            lle = octets[1]
            assert len(octets) > lle + 3
            eo = octets[2:lle+2]
            no = octets[lle+2:]
        e = int.from_bytes(eo, byteorder='big', signed=True)
        n = int.from_bytes(no, byteorder='big', signed=False)
        logger.debug(f'Octets={octets.hex(" ")}, s={s:d}, n={n:d}, e={e:d}')

        if e == 0 and n == 0:
            return 0.0

        # 根据IEEE 754重构双精度浮点数，不直接计算，防止出现尾数过长造成过程中浮点数溢出的情况
        fe = (e if b == 2 else e * 3 if b == 8 else e * 4) + f
        if n.bit_length() > 53:  # 有效位超出了双精度
            rshift = n.bit_length() - 53
            fn = (n >> rshift) ^ ((0x01 << 52) - 1)  # 去掉首位的1
            fe += rshift
        else:
            lshift = 53 - n.bit_length()
            fn = (n << lshift) & ((0x01 << 52) - 1)  # 在52bit上向左对齐
            fe -= lshift
        fe += 52 + 1023  # fn的含义小数点后的52个bit，相当于在整数基础上右移了52位，因此指数增加52，再加上偏移值1023

        logger.debug(f'Float:     fn={fn:052b}, fe={fe:d}')

        if fe <= 0:  # 浮点数过小，调整指数为次正规数或者零，有效数整数部分为0
            fn = (fn | (0x01 << 52)) >> (-1 * fe)  # 将首位的1补上，右移至fe=0，即指数变为-1023
            fe = 0
            logger.debug(f'Subnormal: fn={fn:052b}, fe={fe:d}')
            if fn == 0:  # 绝对值低于浮点数可表示的下限，返回零
                if s:
                    raise -0.0
                else:
                    return 0.0
            else:  # 绝对值在次正规数范围内，将指数调整为-1022
                fn >>= 1  # 尾数右移1位
                fnb = fn.to_bytes(7, byteorder='big', signed=False)
                b1 = 0x80 if s < 0 else 0x00
                assert fnb[0] & 0xf0 == 0
                b2 = (0x00 & 0xf0) | (fnb[0] & 0x0f)
        elif fe > 2047:  # 浮点数过大，通常不会出现在二进制编码中
            return Decimal(2) ** e * Decimal(n) * (-1 if s else 1)
        else:
            fnb = fn.to_bytes(7, byteorder='big', signed=False)
            assert (fe >> 4) & 0x80 == 0
            b1 = (0x80 if s < 0 else 0x00) | (fe >> 4)
            assert fnb[0] & 0xe0 == 0
            b2 = ((fe << 4) & 0xf0) | (fnb[0] & 0x0f)

        packed = bytearray((b1, b2,))
        packed.extend(fnb[1:])
        logger.debug(f'Encoded Octets: {packed.hex(" ")}')
        raw_float = struct.unpack('>d', packed)[0]

        if __debug__:
            res = float(n) * (b ** e) * (2 ** f) * s
            logger.debug(f'Raw:  {raw_float:e}, {struct.pack(">d", raw_float).hex()}')
            logger.debug(f'Calc: {res:e}, {struct.pack(">d", res).hex()}')
            assert res == raw_float

        return raw_float

    @staticmethod
    def _decode_base10(octets: bytes) -> Decimal:
        assert octets[0] & 0xC0 == 0
        nr = octets[0] & 0x3f
        if nr == 0x01 or nr == 0x02 or nr == 0x03:  # nr1, nr2, nr3
            return Real.eval_string(octets[1:].decode('ascii'))
        else:
            raise InvalidReal("Decimal encoding is specified but not a valid representation is chosen.")

    @staticmethod
    def decode(octets: bytes) -> Union[Decimal, float, SpecialRealValue]:  # 8.5.6
        assert len(octets) > 0
        fo = octets[0]  # for short of first_octet
        if fo & 0x80 != 0:  # b8=1
            return Real._decode_base2s(octets)
        elif fo & 0x40 == 0:  # b8,b7=00
            return Real._decode_base10(octets)
        else:
            srv = SpecialRealValue.from_octet(fo)
            if len(octets) != 1:
                raise InvalidReal("Special real value with following octets")
            return srv

        raise InvalidReal("Not a valid binary, decimal or special value representation.")