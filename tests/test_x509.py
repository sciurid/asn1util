from unittest import TestCase, skip
import logging
from asn1util import asn1_decode, asn1_print_items

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)8s %(name)20s %(lineno)04s %(message)s")
logger = logging.getLogger(__name__)


class X509TestCase(TestCase):
    def test_rsa(self):
        with open('chenqiang.me.cer', 'rb') as cert:
            asn1_print_items(asn1_decode(cert))

    def test_sm2(self):
        with open('sm2.rca.der', 'rb') as cert:
            asn1_print_items(asn1_decode(cert))
        with open('sm2.oca.der', 'rb') as cert:
            asn1_print_items(asn1_decode(cert))







