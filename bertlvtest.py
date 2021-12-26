from unittest import TestCase, skip
from asn1util import *
import traceback


class BERTLVTestCase(TestCase):
    def test_indefinite_length_value(self):
        decode_print(b'\x30\x80\x04\x03\x31\x32\x33\x04\x04\x34\x35\x36\x37\x00\x00')

    @skip
    def test_indefinite_length_value_error(self):
        with self.assertRaises(InvalidTLV) as ctx:
            decode_print(b'\x30\x80\x03\x31\x32\x33\x00\x01\x00')
        print(ctx.exception)

    @skip
    def test_bit_string(self):
        o, l = BitString.decode(bytes.fromhex('06 6e 5d e0'))
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
        encoder.append_primitive(TagNumber.Null, value=None)
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
            decode_print(cert)


    def test_case1(self):
        data = bytes.fromhex('6f 16 84 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 a5 02 88 00')
        decode_print(data, SMART_CARD_TAGS)
        for item in dfs_decoder(data):
            print(item)

    def test_der_reconstruct(self):
        with open('chenqiang.me.cer', 'rb') as cert:
            for tlvitem in dfs_decoder(cert):
                encoder = Encoder()
                tag = tlvitem.tag
                try:
                    if tag.is_primitive:
                        if tag.number in UNIVERSAL_DECODERS:
                            handler = UNIVERSAL_DECODERS[tag.number]
                            value_data = handler(tlvitem.value_octets)
                            encoder.append_primitive(tag_class=tag.cls, tag_number=tag.number, value=value_data)
                        else:
                            encoder.append_primitive(tag_class=tag.cls, tag_number=tag.number, value=tlvitem.value_octets)
                        print(tag, tlvitem.tlv_octets.hex(' '))
                        print(tag, encoder.data.hex(' '))
                    else:
                        pass
                except Exception as e:
                    print(tag, e)
                    traceback.print_exc()
                    continue






