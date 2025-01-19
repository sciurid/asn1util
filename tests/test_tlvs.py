from asn1util import *
from unittest import TestCase
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

        encoder = StreamEncoder()
        with encoder.construct(TAG_Sequence, True):
            encoder.append_primitive(TAG_Boolean, b'\xff')
            encoder.append_primitive(TAG_Integer, b'\x01\x02\x03\x04')
            encoder.append_primitive(TAG_UTF8String, '中华人民共和国万岁 世界人民大团结万岁'.encode('utf-8'))
            with encoder.construct(TAG_Sequence, True):
                encoder.append_primitive(TAG_Boolean, b'\x00')
                encoder.append_primitive(TAG_PrintableString, 'The fox jumps over a lazy dog.'.encode('ascii'))
        print(encoder.data.hex(' '))

        for t, l, v in iter_descendant_tlvs(encoder.data, return_octets=False):
            print(t, l, v.hex())

        asn1_print_items(asn1_decode(encoder.data))

    def test_encoding(self):
        encoder = StreamEncoder()
        with encoder.construct(TAG_Sequence):
            encoder.append_primitive(TAG_Boolean, b'\xff')
            encoder.append_primitive(TAG_Integer, b'\x01\x02\x03\x04')
            encoder.append_primitive(TAG_UTF8String, '中华人民共和国万岁 世界人民大团结万岁'.encode('utf-8'))
            with encoder.construct(TAG_Sequence):
                encoder.append_primitive(TAG_Boolean, b'\x00')
                encoder.append_primitive(TAG_PrintableString, 'The fox jumps over a lazy dog.'.encode('ascii'))
        print(encoder.data.hex(' '))

        for t, l, v in iter_descendant_tlvs(encoder.data, return_octets=False):
            print(t, l, v.hex())

        asn1_print_items(asn1_decode(encoder.data))

    def test_decoding(self):
        encoder = StreamEncoder()
        encoder.append_primitive(TAG_Integer, b'\x01\x02\x03\x04')
        with encoder.construct(TAG_Sequence):
            encoder.append_primitive(TAG_Boolean, b'\x00')
            encoder.append_primitive(TAG_PrintableString, 'The fox jumps over a lazy dog.'.encode('ascii'))

        print(encoder.data.hex(' '))
        for t, l, v in iter_tlvs(encoder.data, return_octets=False):
            print(t, l, v.hex())

        print(encoder.data.hex(' '))
        for t, l, v in iter_descendant_tlvs(encoder.data, return_octets=False):
            print(t, l, v.hex())

        print(encoder.data.hex(' '))
        stream = BytesIO(encoder.data)
        t, l, v = read_next_tlv(stream, return_octets=True)
        print(t.hex(), l.hex(), v.hex())
        t, l, v = read_next_tlv(stream, return_octets=True)
        print(t.hex(), l.hex(), v.hex())
        t, l, v = read_next_tlv(stream, return_octets=True)
        self.assertIsNone(t)
        self.assertIsNone(l)
        self.assertIsNone(v)






