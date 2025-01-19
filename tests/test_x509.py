from unittest import TestCase, skip
import logging
from asn1util import *

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)8s %(name)20s %(lineno)04s %(message)s")
logger = logging.getLogger(__name__)


class X509TestCase(TestCase):
    def test_rsa(self):
        with open('chenqiang.me.cer', 'rb') as cert:
            asn1_print_items(asn1_decode(cert))

        with open('chenqiang.me.cer', 'rb') as cert:
            self.check_der_compatible(cert)

    def test_sm2(self):
        with open('sm2.rca.der', 'rb') as cert:
            asn1_print_items(asn1_decode(cert))

        with open('sm2.rca.der', 'rb') as cert:
            self.check_der_compatible(cert)

        with open('sm2.oca.der', 'rb') as cert:
            asn1_print_items(asn1_decode(cert))

        with open('sm2.oca.der', 'rb') as cert:
            self.check_der_compatible(cert)

    def check_der_compatible(self, cert):
        for t, l, v in iter_descendant_tlvs(cert, in_octets=True):
            logger.debug('TLV: %s %s %s', t, l, v.hex())
            if t in UNIVERSAL_DATA_TYPE_MAP:
                item = UNIVERSAL_DATA_TYPE_MAP[t](length=Length(l), value_octets=v)
            elif t in EXTENDED_DATA_TYPE_MAP:
                item = EXTENDED_DATA_TYPE_MAP[t](length=Length(l), value_octets=v)
            else:
                item = ASN1GeneralDataType(tag=Tag(t), length=Length(l), value_octets=v)

            src = t + l + v
            enc = item.octets
            # print(src.hex())
            # print(enc.hex())
            self.assertEqual(src, enc)








