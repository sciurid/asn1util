from asn1util import *
from unittest import TestCase, skip
from decimal import *
import random

import logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)8s %(name)20s %(lineno)04s %(message)s")
logger = logging.getLogger(__name__)


class RealValueTestCase(TestCase):
    def test_floats(self):
        for _ in range(20):
            # 正规数测试
            fv = random.SystemRandom().uniform(-1e10, 1e10)
            octets = Real.encode(fv)
            self.assertEqual(Real.decode(octets), fv)

            # 次正规数测试
            snfv = random.SystemRandom().uniform(-1, 1) * (2 ** -1022)
            logger.debug(f'Subnormal: {snfv:e}')
            self.assertEqual(Real.decode(Real.encode(snfv)), snfv)

    def test_specials(self):
        # 特殊数测试
        fv = 0.0
        octets = Real.encode(fv)
        rv = Real.decode(octets)
        self.assertEqual(rv, fv)

        # 特殊数测试
        fv = -0.0
        octets = Real.encode(fv)
        rv = Real.decode(octets)
        self.assertEqual(rv.to_float(), fv)
        self.assertTrue(rv.to_decimal().is_zero())
        self.assertEqual(Decimal('1.0').copy_sign(rv.to_decimal()), Decimal('-1.0'))

        fv = float('nan')
        octets = Real.encode(fv)
        self.assertTrue(math.isnan(Real.decode(octets).to_float()))

        fv = float('inf')
        octets = Real.encode(fv)
        rv = Real.decode(octets)
        self.assertTrue(rv == SpecialRealValue.PLUS_INFINITY)
        self.assertTrue(math.isinf(rv.to_float()))
        self.assertTrue(rv.to_decimal().is_infinite())
        self.assertEqual(Decimal('1.0').copy_sign(rv.to_decimal()), Decimal('1.0'))

        fv = float('-inf')
        octets = Real.encode(fv)
        rv = Real.decode(octets)
        self.assertTrue(rv == SpecialRealValue.MINUS_INFINITY)
        self.assertTrue(math.isinf(rv.to_float()))
        self.assertTrue(rv.to_decimal().is_infinite())
        self.assertEqual(Decimal('1.0').copy_sign(rv.to_decimal()), Decimal('-1.0'))

    def test_decimals(self):
        for _ in range(10):
            rnd = random.SystemRandom()
            buffer = io.StringIO()
            buffer.write('-' if rnd.choice([0, -1]) else '')
            buffer.write(''.join((rnd.choice('0123456789') for _ in range(rnd.randint(0, 20)))))
            buffer.write('.')
            buffer.write(''.join((rnd.choice('0123456789') for _ in range(rnd.randint(0, 20)))))
            sv = buffer.getvalue()

            dv = Decimal(sv)
            fv = float(dv)
            s, n, e = Real.decompose_decimal_to_sne_of_two(dv, 80)
            rv = 2 ** e * n * (-1 if s else 1)
            print(dv, fv, rv)
            self.assertEqual(rv, fv)




