from unittest import TestCase, skip
import logging
import os
from asn1util import *

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)8s %(name)20s %(lineno)04s %(message)s")
logger = logging.getLogger(__name__)


class X509TestCase(TestCase):
    def test_certificates(self):
        location = os.path.abspath(os.path.join(__file__, os.pardir))
        for fn in ('chenqiang.me.cer', 'sm2.rca.der', 'sm2.oca.der'):
            self.check_certificate(os.path.join(location, fn))


    def check_certificate(self, filepath):
        print("-" * 20 + filepath + '-' * 20)
        with open(filepath, 'rb') as cert:
            data = cert.read()

        asn1_print_items(asn1_decode(data))
        self.check_der_compatible(data)
        item_sequence = asn1_decode(data)[0]
        self.assertEqual(data, item_sequence.octets)


    def check_der_compatible(self, cert):
        for t, l, v in iter_descendant_tlvs(cert, in_octets=True):  # 从ASN.1数据中依次取出元素
            logger.debug('TLV: %s %s %s', t.hex(), l.hex(), v.hex())
            if t in UNIVERSAL_DATA_TYPE_MAP:
                item = UNIVERSAL_DATA_TYPE_MAP[t](length=Length(l), value_octets=v)
            elif t in EXTENDED_DATA_TYPE_MAP:
                item = EXTENDED_DATA_TYPE_MAP[t](length=Length(l), value_octets=v)
            else:
                item = ASN1GeneralDataType(tag=Tag(t), length=Length(l), value_octets=v)

            src = t + l + v
            enc = item.octets
            self.assertEqual(src, enc)
