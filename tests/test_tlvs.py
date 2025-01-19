from asn1util import *
from unittest import *
import logging

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)8s %(name)20s %(lineno)04s %(message)s")
logger = logging.getLogger(__name__)



class TLVTestCase(TestCase):

    def test_indefinite_length(self):
        indefinite_octets = bytes.fromhex('30 80 04 03 31 32 33 04 04 34 35 36 37 00 00')
        print(read_next_tlv(indefinite_octets))

        with self.assertRaises(InvalidEncoding) as ctx:
            print(read_next_tlv(bytes.fromhex('30 80 04 03 31 32 00')))
        print(ctx.exception)

    def test_codecs(self):
        encoder = StreamEncoder()
        with encoder.construct(b'\x30', True):
            encoder.append_primitive(b'\x01', b'\xff')
            encoder.append_primitive(b'\x02', b'\x01\x02\x03\x04')
            with encoder.construct(b'\x30', True):
                encoder.append_primitive(b'\x01', b'\x00')
        print(encoder.data.hex(' '))

        for t, l, v in iter_descendant_tlvs(encoder.data, in_octets=False):
            print(t, l, v.hex())

        # with encoder.construct(b'\x30', True):
        #     encoder.append_primitive(b'\x01',b'\xff')
        #     encoder.append_primitive(b'\x02', b'\x00\x01\x02\x03')
        #     encoder.append_primitive(b'\x13', b'The fox jumps over the lazy dog.')
        #     with encoder.construct(b'\x30', True):
        #         encoder.append_primitive(b'\x01', b'\x00')
        #         encoder.append_primitive(b'\x02', b'\x03\x02\x01\x00')
        #         encoder.append_primitive(b'\x13', b'Hello, world!')




        asn1_print_items(asn1_decode(encoder.data))





