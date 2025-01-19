from asn1util import *
from unittest import TestCase
from decimal import *
import random

import logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)8s %(name)20s %(lineno)04s %(message)s")
logger = logging.getLogger(__name__)


def print_float(data: bytes):
    print("Exp:", end='')
    print('{:011b}'.format(((data[0] & 0x7f) << 4) | ((data[1] & 0xf0) >> 4)))
    print("Sig:", end='')
    print('{:04b}'.format(data[1] & 0x0f), end='')
    for i in range(2, 8):
        print(' {:08b}'.format(data[i] & 0x0f), end='')
    print()

class RealValueTestCase(TestCase):
    def test_ieee758(self):
        for s, n, e in ((1, 1 << 51, -1074), (1, 1 << 51, -1073)):
            f = s * n * 2 ** e
            constructed = to_ieee758_double(s, n, e)
            self.assertEqual(constructed, f)


    def test_specials(self):
        # 特殊数测试
        for fv in (-0.0, float('inf'), float('-inf')):
            rv = ASN1Real(value=fv)
            print(fv, rv)
            self.assertEqual(fv, rv.value)

        for dv in (Decimal('-0'), Decimal('Infinity'), Decimal('-Infinity')):
            rv = ASN1Real(value=dv, base=10)
            print(dv, rv)
            self.assertEqual(dv, rv.value)

        print(float('nan'), ASN1Real(value=float('nan'), base=10))
        print(Decimal('NaN'), ASN1Real(value=Decimal('NaN')))


    def test_real(self):
        for _ in range(10000):
            fv = random.randint(-1,1) * random.randint(0, 10000) / random.randint(1, 10000)
            rv = ASN1Real(value=fv)

            print(fv, rv)
            self.assertEqual(fv, rv.value)

        for _ in range(10000):
            dv = Decimal((random.randint(0,1),
                          [random.randint(0, 9) for _ in range(random.randint(1, 10))],
                          random.randint(-10, 10)))
            if dv.is_zero():
                continue
            rv = ASN1Real(value=dv, base=10)
            dr = ASN1Real(value_octets=rv.value_octets, base=10)
            print(dv, rv, dr)
            self.assertEqual(dv, dr.value)
