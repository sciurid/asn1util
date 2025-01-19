from .general_data_types import *


TAG_Sequence = Tag(b'\x30')
TAG_Set = Tag(b'\x31')


class ASN1Sequence(ASN1DataType):
    def __init__(self, length: Length = None, value: Sequence[ASN1DataType] = None, value_octets: bytes = None,
                 der: bool = False):
        super().__init__(length, value, value_octets, der)

    @property
    def tag(self) -> Tag:
        return TAG_Sequence

    @property
    def tag_name(self) -> str:
        return 'Sequence'

    def __repr__(self):
        return self._repr_common_format(meta_expr=f'(len={self._length.value},items={len(self._value)})', value_expr='')

    def decode_value(self, octets: bytes, der: bool) -> List[ASN1DataType]:
        return asn1_decode(octets, der)

    def encode_value(self, value) -> bytes:
        return asn1_encode(value)

class ASN1Set(ASN1DataType):

    def __init__(self, length: Length = None, value=None, value_octets: bytes = None, der: bool = False):
        super().__init__(length, value, value_octets, der)

    @property
    def tag(self) -> Tag:
        return TAG_Set

    @property
    def tag_name(self) -> str:
        return 'Set'

    def __repr__(self):
        return self._repr_common_format(meta_expr=f'(len={self._length.value},items={len(self._value)})', value_expr='')

    def decode_value(self, octets: bytes, der: bool):
        return asn1_decode(octets, der)

    def encode_value(self, value) -> bytes:
        items: List[ASN1DataType] = self.value
        items.sort(key=lambda item: item.tag)
        return asn1_encode(items)

UNIVERSAL_DATA_TYPE_MAP[b'\x30'] = ASN1Sequence
UNIVERSAL_DATA_TYPE_MAP[b'\x31'] = ASN1Set