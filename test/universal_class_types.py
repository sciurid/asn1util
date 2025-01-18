from unittest import TestCase
from asn1util.datatypes import *


class UniversalClassTypes(TestCase):
    def test(self):
        eoc = ASN1EndOfContent()

        bTrue = ASN1Boolean(value=True)
