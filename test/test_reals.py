from asn1util import *
from unittest import TestCase, skip
from decimal import *
import random

import logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)8s %(name)20s %(lineno)04s %(message)s")
logger = logging.getLogger(__name__)
import os


class RealValueTestCase(TestCase):

    def construct_ieee758_double(self, sign: int, number: int, exponent: int):
        """将数值为s * number * 2 ** exponent的浮点数转化为ieee 758格式"""
        buffer = bytearray()
        el = 11  # 指数域的位数
        nl = 52  # 尾数域的位数
        bias = 2 ** (el - 1) - 1  # 指数偏移值
        """
        尾数每右移1位，指数应当增加1以保持数值不变，若右移完成指数域（指数加偏移值）仍然小于0，则需要用次正规数表示或者向下溢出到0。
        需要将尾数右移至整数部分仅为1，根据相应的指数域判断属于正规数、次正规数、下溢出或上溢出。
        正规数的指数偏移值为{2^(e_bit_len-1)-1}，次正规数的指数偏移值比正规数的小1。          
        """

        # exp_part = exponent + bias  # 先将指数偏移值计算在内，以方便判断

        n_bit_len = number.bit_length()

        if n_bit_len > nl + 1:
            # 尾数精度超过浮点数规定，按正规数的尾数域长度加整数位数1右移，进行舍弃精度
            r_shift = n_bit_len - nl - 1
            number >>= r_shift
            n_bit_len -= r_shift
            assert n_bit_len == number.bit_length()
            exponent += r_shift  # 对应地增加指数域
            print("尾数过长造成精度损失{:d}位".format(r_shift))

        r_shift = n_bit_len - 1  # 若正规数可表示（或上溢出），尾数应当右移的位数（除最高位1以外的其他位数）
        exponent_part = exponent + r_shift + bias
        if exponent_part > (1 << el) - 2:
            print("上溢出")
            return None
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
                print("下溢出")
                return 0.0
            if nl < r_shift:  # 右移以后发生精度损失
                print("指数过小造成精度损失{:d}位".format(nl - r_shift))
                significant = number >> (r_shift - nl)
            else:
                significant = number << (nl - r_shift)

        e_bytes = exponent_part.to_bytes(2, byteorder='big', signed=False)
        n_bytes = significant.to_bytes(7, byteorder='big', signed=False)
        first = (0x80 if sign < 0 else 0x00) | ((e_bytes[0] & 0x07) << 3) | ((e_bytes[1] & 0xf0) >> 4)
        second = ((e_bytes[1] & 0x0f) << 4) | ((n_bytes[0] & 0x0f))
        buffer.append(first)
        buffer.append(second)
        buffer.extend(n_bytes[1:])
        return bytes(buffer)


    def print_float(self, data: bytes):
        print("Exp:", end='')
        print('{:011b}'.format(((data[0] & 0x7f) << 4) | ((data[1] & 0xf0) >> 4)))
        print("Sig:", end='')
        print('{:04b}'.format(data[1] & 0x0f), end='')
        for i in range(2, 8):
            print(' {:08b}'.format(data[i] & 0x0f), end='')
        print()

    def test_floats(self):

        for s, n, e in ((1, 1 << 51, -1074), (1, 1 << 51, -1073)):
            f = s * n * 2 ** e
            standard = struct.pack('>d', f)
            custom = self.construct_ieee758_double(s, n, e)
            self.print_float(standard)
            self.print_float(custom)
            print(standard.hex())
            print(custom.hex())



            self.assertEqual(standard, custom)



        n = 314159
        e = -1074
        pi50 = n * (2 ** e)
        print(pi50)
        print(struct.pack('>d', pi50).hex())

        cpi50 = self.construct_ieee758_double(1, n, e)
        print(cpi50.hex())
        print(struct.unpack('>d', cpi50)[0])












    # def test_specials(self):
    #     # 特殊数测试
    #     fv = 0.0
    #     octets = Real.encode(fv)
    #     rv = Real.decode(octets)
    #     self.assertEqual(rv, fv)
    #
    #     # 特殊数测试
    #     fv = -0.0
    #     octets = Real.encode(fv)
    #     rv = Real.decode(octets)
    #     self.assertEqual(rv.to_float(), fv)
    #     self.assertTrue(rv.to_decimal().is_zero_point())
    #     self.assertEqual(Decimal('1.0').copy_sign(rv.to_decimal()), Decimal('-1.0'))
    #
    #     fv = float('nan')
    #     octets = Real.encode(fv)
    #     self.assertTrue(math.isnan(Real.decode(octets).to_float()))
    #
    #     fv = float('inf')
    #     octets = Real.encode(fv)
    #     rv = Real.decode(octets)
    #     self.assertTrue(rv == SpecialRealValue.PLUS_INFINITY)
    #     self.assertTrue(math.isinf(rv.to_float()))
    #     self.assertTrue(rv.to_decimal().is_infinite())
    #     self.assertEqual(Decimal('1.0').copy_sign(rv.to_decimal()), Decimal('1.0'))
    #
    #     fv = float('-inf')
    #     octets = Real.encode(fv)
    #     rv = Real.decode(octets)
    #     self.assertTrue(rv == SpecialRealValue.MINUS_INFINITY)
    #     self.assertTrue(math.isinf(rv.to_float()))
    #     self.assertTrue(rv.to_decimal().is_infinite())
    #     self.assertEqual(Decimal('1.0').copy_sign(rv.to_decimal()), Decimal('-1.0'))
    #
    # def test_decimals(self):
    #     for _ in range(10):
    #         rnd = random.SystemRandom()
    #         buffer = io.StringIO()
    #         buffer.write('-' if rnd.choice([0, -1]) else '')
    #         buffer.write(''.join((rnd.choice('0123456789') for _ in range(rnd.randint(0, 20)))))
    #         buffer.write('.')
    #         buffer.write(''.join((rnd.choice('0123456789') for _ in range(rnd.randint(0, 20)))))
    #         sv = buffer.getvalue()
    #
    #         dv = Decimal(sv)
    #         fv = float(dv)
    #         s, n, e = Real.decompose_decimal_to_base2_sne(dv, 80)
    #         rv = 2 ** e * n * (-1 if s else 1)
    #         print(dv, fv, rv)
    #         self.assertEqual(rv, fv)
