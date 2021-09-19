from bertlv import *
from unittest import TestCase, skip
from decimal import *


class RealValueTestCase(TestCase):
    @skip
    def test_decompose_sne(self):
        for value in [Decimal(123.456), Decimal('123.456'), Decimal(1024), Decimal(-10.625)]:
            s, n, e = Real.decompose_decimal_to_sne_of_two(value, 16)
            print(value)
            print(s, n, e)
            print(n * DefaultContext.power(2, e))

    def test_ieee754(self):
        for value in (-10.625, 123.456):
            # print(Real.decompose_decimal_to_sne_of_two(Decimal(value), 2))
            s, n, e = Real.decompose_ieee754_to_sne_of_two(value)
            print(s, n, e)
            print(2 ** e * n)
            s, n, e = Real.decompose_ieee754_to_sne_of_two(value, False)
            print(s, n, e)
            print(2 ** e * n)

    @skip
    def test_encode_base2(self):
        encoded = Real.encode_base2(10.625, 16)
        tag = Tag(TagClass.UNIVERSAL, TagPC.PRIMITIVE, TagNumber.Real)
        length = Length(len(encoded))
        segment = tag.octets + length.octets + encoded
        print(segment.hex())

    def test_encode_base10(self):
        encoded = Real.encode_base10(10.625, 2)
        tag = Tag(TagClass.UNIVERSAL, TagPC.PRIMITIVE, TagNumber.Real)
        length = Length(len(encoded))
        segment = tag.octets + length.octets + encoded
        print(segment.hex())
