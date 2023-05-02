from asn1util import *
from unittest import *
from datetime import datetime
from pytz import timezone
import logging

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)8s %(name)20s %(lineno)04s %(message)s")
logger = logging.getLogger(__name__)


class TLVTestCase(TestCase):

    def create_tlv(self):
        encoder = Encoder()
        # encoder.begin_constructed(TagNumber.Sequence)
        with encoder.construct(TagNumber.Sequence):
            encoder.append_primitive(TagNumber.Integer, value=20)
            encoder.append_primitive(TagNumber.Real, value=Decimal('123.4'))
            encoder.append_primitive(TagNumber.Real, value=10.625)
            encoder.append_primitive(TagNumber.OctetString, value=b'\x01\x02\x03' * 50)
            encoder.append_primitive(TagNumber.BitString, value=0xf0f0, bit_length=20)
            encoder.append_primitive(TagNumber.Null, value=None)
            encoder.append_primitive(TagNumber.UTF8String, value='我的世界')
            encoder.append_primitive(TagNumber.ObjectIdentifier, value='1.2.840.113549')

            tz = timezone('Asia/Shanghai')
            dt = tz.localize(datetime.now())
            encoder.append_primitive(TagNumber.GeneralizedTime, value=dt)
            encoder.append_primitive(TagNumber.UTCTime, value=dt)
            encoder.append_primitive(TagNumber.GeneralizedTime, raw='202305032300.1+0800'.encode('utf-8'))
        return encoder.data

    def test_primitives(self):
        data = self.create_tlv()
        print("Encoded: " + data.hex(sep=' '))
        decode_print(data)

        for token in iter(Decoder(data)):
            pass
