from asn1util import *
from unittest import *
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)8s %(name)20s %(lineno)04s %(message)s")
logger = logging.getLogger(__name__)


class TLVTestCase(TestCase):

    def test_indefinite_length(self):
        indefinite_octets = bytes.fromhex('30 80 04 03 31 32 33 04 04 34 35 36 37 00 00')
        print(read_next_tlv(indefinite_octets))

        with self.assertRaises(InvalidEncoding) as ctx:
            print(read_next_tlv(bytes.fromhex('30 80 04 03 31 32 00')))
        print(ctx.exception)




