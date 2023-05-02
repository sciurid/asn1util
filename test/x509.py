from unittest import TestCase, skip
import logging
from asn1util import decode_print

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)8s %(name)20s %(lineno)04s %(message)s")
logger = logging.getLogger(__name__)


class X509TestCase(TestCase):
    def test_certificate(self):
        with open('chenqiang.me.cer', 'rb') as cert:
            decode_print(cert)
