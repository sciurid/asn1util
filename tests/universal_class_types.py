from unittest import TestCase
from asn1util.datatypes import *

import random


class UniversalClassTypes(TestCase):
    def test(self):
        eoc = ASN1EndOfContent()
        print(eoc)

        bTrue = ASN1Boolean(value=True)
        bFalse = ASN1Boolean(value=False)
        print(bTrue, bFalse)
        self.assertEqual(bTrue, ASN1Boolean(value_octets=bTrue.value_octets))
        self.assertEqual(bFalse, ASN1Boolean(value_octets=bFalse.value_octets))

        for r in [random.randint(0, 1 << 32), -1 * random.randint(0, 1 << 32), 127, 128, -128, -129]:
            iR = ASN1Integer(value=r)
            print(iR)
            self.assertEqual(iR, ASN1Integer(value_octets=iR.value_octets))
            eR = ASN1Enumerated(value=r)
            print(eR)
            self.assertEqual(eR, ASN1Enumerated(value_octets=eR.value_octets))






