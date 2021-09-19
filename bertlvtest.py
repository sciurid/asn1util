from unittest import TestCase, skip
from bertlv import *
from io import BytesIO


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
        o, l = Decoder.decode_bit_string(bytes.fromhex('06 6e 5d e0'))
        print(o.hex())
        print(Util.repr_bit_string(o, l))
        print(Encoder._encode_bit_string(o, l).hex())

    @skip
    def test_integer(self):
        s = 65534
        t = Decoder.decode_integer(Encoder._encode_integer_enum(s))
        self.assertEqual(s, t)

    def test_encoding(self):
        encoder = Encoder()
        encoder.append_primitive(TagNumber.Integer, 20)
        encoder.append_primitive(TagNumber.OctetString, b'\x01\x02\x03')
        encoder.begin_constructed(TagNumber.Sequence)
        encoder.append_primitive(TagNumber.OctetString, b'\x01\x02\x03')
        encoder.append_primitive(TagNumber.OctetString, b'\x04\x05\x06')
        encoder.append_primitive(TagNumber.OctetString, b'\x07\x08\x09')
        encoder.end_constructed()
        print("Encoded: " + encoder.data.hex(sep=' '))
        decode_print(encoder.data)

    def test_object_identifier(self):
        oid_1 = ObjectIdentifier([1, 2, 840, 113549])
        encoded_1 = oid_1.encode().hex(' ')
        oid_2 = ObjectIdentifier.decode_string('1.2.840.113549')
        encoded_2 = oid_2.encode().hex(' ')

        self.assertEqual(encoded_1, "2a 86 48 86 f7 0d")
        self.assertEqual(encoded_1, encoded_2)
        oid = ObjectIdentifier.decode(oid_1.encode())
        print(oid)




