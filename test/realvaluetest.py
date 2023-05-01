from asn1util import *
from unittest import TestCase, skip
from decimal import *

import logging
logging.basicConfig(format="%(asctime) %(levelname) %(message)")

class RealValueTestCase(TestCase):

    def test_ieee754(self):
        for value in (-10.625, 123.456, -0.25, Decimal('123.456')):
            # print(Real.decompose_decimal_to_sne_of_two(Decimal(value), 2))
            s, n, e = Real.decompose_float_to_sne_of_two(value)
            print(f'{value} => {s}, {n}, {e} => {(2 ** e * n * (-1 if s else 1))}')

            s, n, e = Real.decompose_float_to_sne_of_two(value, False)
            print(f'{value} => {s}, {n}, {e} => {(2 ** e * n * (-1 if s else 1))}')

    def test_enc_dec(self):
        setcontext(ExtendedContext)
        print("Precision:", getcontext().prec)
        for val in (Decimal('123.456'), 10.625,  0.342):
            encoded = Real.encode_base2(Decimal(val), 16, 4)
            real = Real.decode(encoded)
            print(f'Base16: {val} => {encoded.hex(" ")} => {real.value}: {val == real.value}')
            encoded = Real.encode_base10(Decimal(val))
            real = Real.decode(encoded)
            print(f'Base10: {val} => {encoded.hex(" ")} => {real.value}: {val == real.value}')
