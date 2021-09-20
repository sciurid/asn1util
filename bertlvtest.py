from unittest import TestCase, skip
from io import BytesIO
from asn1util import *


def decode_print(data):
    for tag, length, value_octets, offsets, stack in dfs_decoder(BytesIO(data)):
        indent = ' ' * 2 * len(stack)
        print(f'{indent} {tag} {length} [V]{"" if value_octets is None else value_octets.hex(" ")}')


class BERTLVTestCase(TestCase):
    def test_indefinite_length_value(self):
        decode_print(b'\x30\x80\x03\x03\x31\x32\x33\x03\x04\x34\x35\x36\x37\x00\x00')

    @skip
    def test_indefinite_length_value_error(self):
        with self.assertRaises(InvalidTLV) as ctx:
            decode_print(b'\x30\x80\x03\x31\x32\x33\x00\x01\x00')
        print(ctx.exception)

    @skip
    def test_bit_string(self):
        o, l = decode_bit_string(bytes.fromhex('06 6e 5d e0'))
        print(o.hex())
        print(repr_bit_string(o, l))
        print(Encoder._encode_bit_string(o, l).hex())

    def test_encoding(self):
        encoder = Encoder()
        encoder.begin_constructed(TagNumber.Sequence)
        encoder.append_primitive(TagNumber.Integer, value=20)
        encoder.append_primitive(TagNumber.Real, value=123.4)
        encoder.append_primitive(TagNumber.Real, value=10.625, base=16)
        encoder.append_primitive(TagNumber.OctetString, value=b'\x01\x02\x03')
        encoder.append_primitive(TagNumber.Null)
        encoder.append_primitive(TagNumber.UTF8String, value='我的世界')
        encoder.append_primitive(TagNumber.UniversalString, value='我的世界')
        encoder.append_primitive(TagNumber.ObjectIdentifier, value='1.2.840.113549')
        encoder.end_constructed()
        print("Encoded: " + encoder.data.hex(sep=' '))
        decode_print(encoder.data)

    def test_object_identifier(self):
        oid_1 = ObjectIdentifier([1, 2, 840, 113549])
        encoded_1 = oid_1.to_octets().hex(' ')
        oid_2 = ObjectIdentifier.decode_string('1.2.840.113549')
        encoded_2 = oid_2.to_octets().hex(' ')

        self.assertEqual(encoded_1, "2a 86 48 86 f7 0d")
        self.assertEqual(encoded_1, encoded_2)
        oid = ObjectIdentifier.decode(oid_1.to_octets())
        print(oid)

    def test_certificate(self):
        with open('chenqiang.me.cer', 'rb') as cert:
            for tag, length, value_octets, offsets, stack in dfs_decoder(cert):
                indent = ' ' * 2 * len(stack)
                print(f'{indent} {tag} {length} [V]{"" if value_octets is None else value_octets.hex(" ")}')





