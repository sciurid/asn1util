from unittest import TestCase
from asn1util.data_types.primitive_data_types import *

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

    def test_oid(self):
        oid = ASN1ObjectIdentifier(value='1.0.14888.3.14')
        print(oid)
        print(oid.value)
        print(oid.value_octets.hex())
        print(oid.oid_string)

        r_oid = ASN1ObjectIdentifier(value=oid.value)
        self.assertEqual(oid, r_oid)
        r_oid = ASN1ObjectIdentifier(value_octets=oid.value_octets)
        self.assertEqual(oid, r_oid)
        r_oid = ASN1ObjectIdentifier(value=oid.oid_string)
        self.assertEqual(oid, r_oid)







