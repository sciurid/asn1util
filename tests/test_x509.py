from unittest import TestCase, skip
import logging
from asn1util import asn1_decode

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)8s %(name)20s %(lineno)04s %(message)s")
logger = logging.getLogger(__name__)


def iter_print(items, indent=0):
    for item in items:
        if item.tag.is_primitive:
            print('{}{}'.format('    ' * indent, item))
        else:
            print('{}{}'.format('    ' * indent, item))
            iter_print(item.value, indent + 1)

class X509TestCase(TestCase):
    def test_rsa(self):
        with open('chenqiang.me.cer', 'rb') as cert:
            iter_print(asn1_decode(cert))

    def test_sm2(self):
        with open('sm2.rca.der', 'rb') as cert:
            iter_print(asn1_decode(cert))
        with open('sm2.oca.der', 'rb') as cert:
            iter_print(asn1_decode(cert))







