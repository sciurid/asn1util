from asn1util import *
from unittest import *
from datetime import datetime
from pytz import timezone
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)8s %(name)20s %(lineno)04s %(message)s")
logger = logging.getLogger(__name__)


class TLVTestCase(TestCase):

    def test_indefinite_length(self):
        pretty_print(Decoder(bytes.fromhex('30 80 04 03 31 32 33 04 04 34 35 36 37 00 00')))

    def test_indefinite_length_error(self):
        with self.assertRaises(InvalidTLV) as ctx:
            pretty_print(Decoder(bytes.fromhex('30 80 04 03 31 32 00')))
        print(ctx.exception)

    def create_tlv(self):
        encoder = Encoder()
        with encoder.construct(TagNumber.Sequence):
            encoder.append_encoded_primitive(TagNumber.Integer, value=20)
            encoder.append_encoded_primitive(TagNumber.Real, value=Decimal('123.456'))
            encoder.append_encoded_primitive(TagNumber.Real, value=10.625)
            encoder.append_encoded_primitive(TagNumber.ASN1OctetString, value=bytes.fromhex('01 03 07') * 50)
            encoder.append_encoded_primitive(TagNumber.ASN1BitString, value=0xf0f0, bit_length=20)
            encoder.append_encoded_primitive(TagNumber.ASN1Null, value=None)
            encoder.append_encoded_primitive(TagNumber.UTF8String, value='我的世界')
            encoder.append_encoded_primitive(TagNumber.NumericString, value='0123456789 ')
            encoder.append_encoded_primitive(TagNumber.PrintableString, value='aesWithSha256')
            encoder.append_encoded_primitive(TagNumber.ObjectIdentifier, value='1.2.840.113549')

            with encoder.construct(TagNumber.Sequence):
                tz = timezone('Asia/Shanghai')
                dt = tz.localize(datetime.now())
                encoder.append_encoded_primitive(TagNumber.GeneralizedTime, value=dt)
                encoder.append_encoded_primitive(TagNumber.UTCTime, value=dt)
                encoder.append_encoded_primitive(TagNumber.GeneralizedTime, raw='202305032300.1+0800'.encode('utf-8'))

        return encoder.data

    def test_primitives(self):
        data = self.create_tlv()
        print("Encoded: " + data.hex(sep=' '))
        pretty_print(Decoder(data))

