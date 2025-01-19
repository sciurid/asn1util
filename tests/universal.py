from unittest import TestCase
from asn1util.data_types.primitive_data_types import *

import random
from datetime import datetime, timezone


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

    def test_universal(self):
        a = ASN1Integer(1234567890)
        print(a, a.octets.hex())

        b = ASN1Real(1.2345678)
        c = ASN1Real(Decimal('1.2345678'))
        print(b, c)
        d = ASN1Real(12345678)
        print(d, d.octets.hex())
        e = ASN1Real(12345678, base=2)
        print(e, e.octets.hex())

        f = ASN1PrintableString('A fox jumps over a lazy dog.')
        print(f, f.octets.hex(), f.value)
        g = ASN1UTF8String('中华人民共和国万岁 世界人民大团结万岁')
        h = ASN1UniversalString('中华人民共和国万岁 世界人民大团结万岁')
        i = ASN1BMPString('中华人民共和国万岁 世界人民大团结万岁')
        print(g, g.octets.hex(), g.value)
        print(h, h.octets.hex(), h.value)
        print(i, i.octets.hex(), i.value)

        j = ASN1ObjectIdentifier('1.2.840.113549.1.1.11')
        print(j)

        k = ASN1OctetString(bytes.fromhex('00 01 02 03 04 05 06 07 08'))
        print(k, k.octets.hex())
        l = ASN1BitString((bytes.fromhex('00 01 02 03 04 05 06 07 08'), 4))
        print(l, l.octets.hex())

        now = datetime.now().astimezone(timezone.utc)
        m = ASN1GeneralizedTime(now)
        print(m, m.octets)
        n = ASN1UTCTime(now)
        print(n, n.octets)


