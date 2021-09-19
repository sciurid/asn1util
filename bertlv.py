import logging
from enum import IntEnum
from collections import namedtuple
from typing import Union, BinaryIO, Iterable
import re
from decimal import Decimal, Context
import struct

logger = logging.getLogger(__name__)


def bin_expr(octets: bytes):
    return ''.join(map(lambda b: '{:08b}'.format(b), octets))


BOUNDARIES = [2 ** (n * 8 + 7) * (-1) for n in range(8)]


def signed_int_to_bytes(value: int):
    """
    用最少的字节数表示有符号整数
    :param value: 整数
    :return:
    """
    for i, v in enumerate(BOUNDARIES):  # 处理8字节以内的边界负数
        if value == v:
            return b'\x80' + i * b'\x00'

    est_octet_len = value.bit_length() // 8 + 1
    encoded = value.to_bytes(est_octet_len, byteorder='big', signed=True)
    if est_octet_len > 8 and encoded[0] == 0xff and encoded[1] & 0x80 != 0:  # 处理8字节以上的边界负数
        return encoded[1:]
    else:
        return encoded


def unsigned_int_to_bytes(value: int):
    """
    用最少的字节数表示无符号整数
    :param value: 非负整数
    :return:
    """
    return value.to_bytes((value.bit_length() + 7) // 8, byteorder='big', signed=False)


class InvalidTLV(Exception):
    def __init__(self, message):
        self.message = message


class InvalidValue(InvalidTLV):
    def __init__(self, message):
        self.message = message


class TagClass(IntEnum):
    UNIVERSAL = 0x00
    APPLICATION = 0x01
    CONTEXT_SPECIFIC = 0x02
    PRIVATE = 0x03


class TagPC(IntEnum):
    PRIMITIVE = 0x00
    CONSTRUCTED = 0x01


class TagNumber(IntEnum):
    EndOfContent = 0x00
    Boolean = 0x01
    Integer = 0x02
    BitString = 0x03
    OctetString = 0x04
    Null = 0x05
    ObjectIdentifier = 0x06
    ObjectDescriptor = 0x07
    External = 0x08
    Real = 0x09
    Enumerated = 0x0a
    UTF8String = 0x0c
    RelativeOID = 0x0d
    Time = 0x0e
    Sequence = 0x10
    Set = 0x11
    NumericString = 0x12
    PrintableString = 0x13
    T61String = 0x14
    IA5String = 0x16
    UTCTime = 0x17
    GeneralizedTime = 0x18
    UniversalString = 0x1c
    Date = 0x1f
    TimeOfDay = 0x20
    DateTime = 0x21
    Duration = 0x22


TagNumber.values = set(item.value for item in TagNumber)
TagNumber.primitive_set = {
    TagNumber.EndOfContent, TagNumber.Boolean, TagNumber.Integer, TagNumber.BitString,
    TagNumber.OctetString, TagNumber.Null, TagNumber.ObjectIdentifier,
    TagNumber.ObjectDescriptor, TagNumber.Real, TagNumber.Enumerated, TagNumber.UTF8String,
    TagNumber.RelativeOID, TagNumber.Time, TagNumber.NumericString, TagNumber.PrintableString,
    TagNumber.T61String, TagNumber.IA5String, TagNumber.UTCTime, TagNumber.GeneralizedTime,
    TagNumber.UniversalString, TagNumber.Date, TagNumber.TimeOfDay, TagNumber.DateTime,
    TagNumber.Duration}
TagNumber.constructed_set = {
    TagNumber.BitString, TagNumber.OctetString, TagNumber.ObjectDescriptor,
    TagNumber.UTF8String, TagNumber.Sequence, TagNumber.Set, TagNumber.NumericString,
    TagNumber.PrintableString, TagNumber.T61String, TagNumber.IA5String, TagNumber.UTCTime,
    TagNumber.GeneralizedTime, TagNumber.UniversalString}


class Tag:
    def __init__(self, clazz: TagClass, pc: TagPC, number: int):
        self._cls = clazz
        self._pc = pc
        self._number = number
        self._octets = self.encode()
        self._validate()

    def _validate(self):
        if self._cls != TagClass.UNIVERSAL:
            return
        if self._number not in TagNumber.values:
            return
        tn = TagNumber(self._number)
        if self.is_primitive:
            if tn in TagNumber.primitive_set:
                return
        else:
            if tn in TagNumber.constructed_set:
                return
        raise InvalidTLV(f"Universal class type {tn.name} should not be {self.pc.name}.")

    @property
    def cls(self) -> TagClass:
        return TagClass(self._cls)

    @property
    def pc(self) -> TagPC:
        return TagPC(self._pc)

    @property
    def is_primitive(self) -> bool:
        return self._pc == TagPC.PRIMITIVE

    @property
    def is_low_tag_number(self) -> bool:
        return self._number < 0x1f

    @property
    def number(self) -> int:
        return self._number

    @property
    def octets(self) -> bytes:
        return self._octets

    def encode(self):
        tag_initial = (self._cls << 6) | (self._pc << 5)
        if self._number < 0x1f:
            tag_initial |= self._number
            return tag_initial.to_bytes(1, byteorder='big')
        else:
            res = bytearray()
            number = self._number
            while number > 0:
                res.append((number & 0x7f) | 0x80)
                number >>= 7
            res[0] &= 0x7f
            res.append(tag_initial | 0x1f)
            res.reverse()
            return bytes(res)

    @staticmethod
    def decode(data: BinaryIO):
        buffer = data.read(1)
        if len(buffer) == 0:  # EOF of data
            return None
        tag_initial = buffer[0]

        short_number = tag_initial & 0x1f
        if short_number == 0x1f:  # High tag number form
            buffer = data.read(1)
            if len(buffer) == 0:
                raise InvalidTLV("High tag number with no bytes following.")
            number_octet = buffer[0]
            if (number_octet & 0x7f) == 0:
                raise InvalidTLV("High tag number with b7 to b1 being 0 in the first following octet.")

            number = 0
            while (number_octet & 0x80) != 0:
                number = (number << 7) + (number_octet & 0x7f)
                buffer = data.read(1)
                if len(buffer) == 0:
                    raise InvalidTLV("High tag number bytes not end. (No following byte or b8 == 1 for the last byte)")
                number_octet = buffer[0]
            else:
                number = (number << 7) + (number_octet & 0x7f)

            if number < 0x1f:
                raise InvalidTLV("High tag number is less than 31.")
        else:
            number = short_number
        clazz = TagClass((tag_initial & 0xc0) >> 6)
        pc = TagPC((tag_initial & 0x20) >> 5)

        return Tag(clazz, pc, number)

    def __repr__(self):
        text_cls = 'UACP'
        text_pc = 'PC'
        tn = TagNumber(self._number) if self._number in TagNumber.values else None
        if tn is None:
            return f'[T]{text_cls[self.cls]}{text_pc[self.pc]} {self.number:02d} "0x{self.octets.hex()}"'
        else:
            return f'[T]{text_cls[self.cls]}{text_pc[self.pc]} {tn.name}({self.number:02d}) "0x{self.octets.hex()}"'


class Length:
    INDEFINITE = b'\x80'

    def __init__(self, length_value: Union[int, None]):
        self._length_value = length_value
        self._data = Length.encode(length_value)

    @staticmethod
    def encode(length_value: int) -> bytes:
        if length_value is None:
            return Length.INDEFINITE
        if length_value < 0:
            raise InvalidTLV("Length value is less than 0.")
        if length_value < 128:
            return bytes([length_value])
        else:
            length_octets = (length_value.bit_length() + 7) // 8
            if length_octets > 127:
                raise InvalidTLV("Length value is more than 127 bytes.")

            res = bytearray([length_octets | 0x80])
            res.extend(length_value.to_bytes(length_octets, byteorder='big'))
            return bytes(res)

    @property
    def is_definite(self):
        return self._data != Length.INDEFINITE

    @property
    def value(self):
        return self._length_value

    @property
    def octets(self):
        return self._data

    @staticmethod
    def decode(data: BinaryIO):
        buffer = data.read(1)
        if len(buffer) == 0:
            raise InvalidTLV("Length octet is missing.")
        length_initial = buffer[0]

        if length_initial == 0x80:  # Indefinite length
            length = Length(None)
        elif length_initial & 0x80 == 0:  # Short form length
            length = Length(length_initial)
        else:  # Long form length
            length_rest = length_initial & 0x7f
            length_octets = data.read(length_rest)
            if len(length_octets) < length_rest:
                raise InvalidTLV(
                    f"Long form length with not enough additional length octets. (0x{length_octets.hex()})")
            length = Length(int.from_bytes(length_octets, byteorder='big'))
        return length

    def __repr__(self):
        if self.is_definite:
            return f"[L]{self._length_value}"
        else:
            return "[L]INF"


DecoderStackItem = namedtuple('DecoderStackItem', ['tag', 'length', 'value_offset'])
TLVOffsets = namedtuple('TLVOffsets', ['t', 'l', 'v'])


def dfs_decoder(data: BinaryIO):
    stack = []
    while True:
        tof = data.tell()
        tag = Tag.decode(data)
        if tag is None:  # EOF of data
            break

        lof = data.tell()
        length = Length.decode(data)

        vof = data.tell()
        offsets = TLVOffsets(tof, lof, vof)

        if tag.is_primitive:
            if not length.is_definite:
                raise InvalidTLV(f"Primitive tag '{tag}' with indefinite length is not supported.")
            value_octets = data.read(length.value)
            if len(value_octets) < length.value:
                raise InvalidTLV(f"Not enough value octets. {length.value:d} required but {len(value_octets):d} remains.")
            yield tag, length, value_octets, offsets, stack

            if len(stack) == 0:  # Top level
                continue

            # Check if parent constructed tlv ends.
            parent = stack[-1]
            if parent.length.is_definite:
                cur_pos = data.tell()
                exp_pos = parent.value_offset + parent.length.value
                if cur_pos == exp_pos:  # Parent tlv ends.
                    stack.pop()
                elif cur_pos > exp_pos:  # Error: current position exceeds the length specified in parent tlv.
                    raise InvalidTLV(f"Length of sub-tlvs in value {cur_pos - parent.value_offset} "
                                     f"exceeds the specified length {parent.length.value}.")
            else:
                if tag.number == 0 and length.value == 0:  # EOC
                    stack.pop()
        else:
            yield tag, length, None, offsets, stack
            stack.append(DecoderStackItem(tag, length, vof))


class EncodingException(Exception):
    def __init__(self, message):
        self.message = message


class NotSupportedValueException(EncodingException):
    def __init__(self, value):
        self.message = f'Value {value} of type {type(value)} is not supported.'


class Encoder:
    def __init__(self):
        self._stack = []
        self._data = bytearray()

    @staticmethod
    def _encode_boolean(value: Union[bool, int]):
        if isinstance(value, bool):
            return b'\xff' if value else b'\x00'
        if isinstance(value, int):
            return b'\xff' if value != 0 else b'\x00'
        raise NotSupportedValueException(value)

    @staticmethod
    def _encode_bit_string(value: Union[bytes, tuple, list]):
        if isinstance(value, bytes):
            return Encoder._encode_bit_string(value, len(value) * 8)
        if isinstance(value, tuple) or isinstance(value, list):
            if len(tuple) != 2:
                raise Exception('Compsite BitString value should be (octets, bit-length) tuple or list')
            return Encoder._encode_bit_string(value[0], value[1])
        else:
            raise NotSupportedValueException(value)

    @staticmethod
    def _encode_bit_string(octets: bytes, bit_length: int):
        encoded = bytearray()
        assert (len(octets) - 1) * 8 < bit_length <= len(octets) * 8
        if bit_length % 8 == 0:
            encoded.append(0x00)
            encoded.extend(octets)
        else:
            unused = 8 - (bit_length % 8)
            encoded.append(unused)
            encoded.extend(octets)
            encoded[-1] &= ((0xff << unused) & 0xff)
        return encoded

    @staticmethod
    def _encode_integer_enum(value: Union[int, IntEnum]):
        if isinstance(value, int):
            return signed_int_to_bytes(value)
        if isinstance(value, IntEnum):
            return signed_int_to_bytes(value.value)
        raise NotSupportedValueException(value)

    def append_primitive(self, tag_number: int, value, tag_class: TagClass = TagClass.UNIVERSAL):
        tag = Tag(tag_class, TagPC.PRIMITIVE, tag_number)
        encoded = b''
        if tag_number == TagNumber.EndOfContent:
            pass
        elif tag_number == TagNumber.Boolean:
            encoded = Encoder._encode_boolean(value)
        elif tag_number == TagNumber.Integer:
            if isinstance(value, int):
                encoded = Encoder._encode_integer_enum(value)
        elif tag_number == TagNumber.BitString:
            encoded = Encoder._encode_bit_string(value)
        elif tag_number == TagNumber.OctetString:
            if isinstance(value, bytes):
                encoded = value
            else:
                raise NotSupportedValueException(value)
        elif tag_number == TagNumber.Null:
            pass  # TODO
        elif tag_number == TagNumber.ObjectIdentifier:
            pass  # TODO
        elif tag_number == TagNumber.ObjectDescriptor:
            pass  # TODO
        elif tag_number == TagNumber.Real:
            pass  # TODO
        elif tag_number == TagNumber.Enumerated:
            if isinstance(value, int):
                encoded = Encoder._encode_integer_enum(value)
        elif tag_number == TagNumber.UTF8String:
            if isinstance(value, str):
                encoded = value.encode('utf-8')
            else:
                raise NotSupportedValueException(value)
        elif tag_number == TagNumber.RelativeOID:
            pass
        elif tag_number == TagNumber.Time:
            pass
        elif tag_number == TagNumber.NumericString:
            pass
        elif tag_number == TagNumber.PrintableString:
            pass
        elif tag_number == TagNumber.T61String:
            pass
        elif tag_number == TagNumber.IA5String:
            pass
        elif tag_number == TagNumber.UTCTime:
            pass
        elif tag_number == TagNumber.GeneralizedTime:
            pass
        elif tag_number == TagNumber.UniversalString:
            if isinstance(value, str):
                encoded = value.encode('utf-32')
            else:
                raise NotSupportedValueException(value)
            pass
        elif tag_number == TagNumber.Date:
            pass
        elif tag_number == TagNumber.TimeOfDay:
            pass
        elif tag_number == TagNumber.DateTime:
            pass
        elif tag_number == TagNumber.Duration:
            pass

        self._recursive_return(tag, encoded)

    def begin_constructed(self, tag_number: int, tag_class: TagClass = TagClass.UNIVERSAL):
        tag = Tag(tag_class, TagPC.CONSTRUCTED, tag_number)
        self._stack.append((tag, bytearray()))

    def end_constructed(self):
        if len(self._stack) == 0:
            raise EncodingException('No begin_constructed() with end_constructed()')
        tag, value = self._stack.pop()
        self._recursive_return(tag, value)

    def _recursive_return(self, tag: Tag, value: bytes):
        length = Length(len(value))
        segment = tag.octets + length.octets + value
        if len(self._stack) == 0:
            self._data.extend(segment)
        else:
            self._stack[-1][1].extend(segment)

    @property
    def data(self):
        if len(self._stack) == 0:
            return bytes(self._data)
        else:
            raise EncodingException('Constructed element has not finished.')


class Decoder:
    @staticmethod
    def decode_bit_string(octets: bytes) -> (bytes, int):
        bit_length = (len(octets) - 1) * 8
        if octets[0] > 0:
            bit_length -= octets[0]
        return octets[1:], bit_length

    @staticmethod
    def decode_integer(octets: bytes) -> int:
        return int.from_bytes(octets, byteorder='big', signed=True)


class Util:
    @staticmethod
    def repr_bit_string(octets: bytes, bit_length: int):
        return bin_expr(octets)[0:bit_length]


class InvalidObjectIdentifier(InvalidValue):
    def __init__(self, message):
        self.message = message


class ObjectIdentifier:
    def __init__(self, components: Iterable[int]):
        self._components = tuple(value for value in components)
        self._validate()

    def _validate(self):
        if len(self._components) < 2:
            raise InvalidObjectIdentifier('ObjectIdentifier should consist of at least 2 components.')
        if self._components[0] in (0, 1):
            if self._components[1] < 0 or self._components[1] > 39:
                raise InvalidObjectIdentifier(
                    'ObjectIdentifier value 2 should be between 0 to 39 when value 1 is 0 or 1.')
        elif self._components[0] == 2:
            return
        else:
            raise InvalidObjectIdentifier('ObjectIdentifier value 1 shoud be 0, 1 or 2.')

    @property
    def components(self):
        return self._components

    def __repr__(self):
        return '.'.join([str(i) for i in self._components])

    def encode(self):
        data = [self.components[0] * 40 + self.components[1]]
        data.extend(self.components[2:])
        data.reverse()
        octets = bytearray()
        for comp in data:
            octets.append(comp & 0x7f)
            comp >>= 7
            while comp > 0:
                octets.append(comp & 0x7f | 0x80)
                comp >>= 7
        octets.reverse()
        return octets

    OID_STRING_PATTERN: re.Pattern = re.compile(r'^[012](\.[0-9]+)+$')

    @staticmethod
    def decode_string(value: str):
        mo = ObjectIdentifier.OID_STRING_PATTERN.match(value)
        if mo is None:
            raise InvalidObjectIdentifier(f'"{value}" is not a valid ObjectIdentifier.')
        return ObjectIdentifier([int(item) for item in value.split('.')])

    @staticmethod
    def decode(data: bytes):
        components = []
        comp = 0
        for octet in data:
            comp = (comp << 7) | (octet & 0x7f)
            if octet & 0x80 == 0:
                components.append(comp)
                comp = 0
        if data[-1] & 0x80 > 0:
            raise InvalidObjectIdentifier(f'Last octet of encoded object identifier with b8 = 1.')

        combined = components[0]

        if combined < 80:
            components[0] -= (combined // 40) * 40
            components.insert(0, combined // 40)
        else:
            components[0] -= 80
            components.insert(0, 2)

        return ObjectIdentifier(components)


class Real:
    def __init__(self, value: Decimal):
        self._value = value.normalize()

    @classmethod
    def eval_float(cls, float_value: float, precision: int = 16):
        return cls(Decimal(float_value, Context(prec=precision)))

    @classmethod
    def eval_string(cls, string_value: str):
        return cls(Decimal(str))

    @staticmethod
    def decompose_decimal_to_sne_of_two(value: Decimal, max_n_octets: int = 3):
        """
        将数值分解为符号项S，整数项N和2的指数项E，并符合DER格式中关于N的最低位不为0的要求。
        :param value: 数值
        :param max_n_octets: 整数项N的最大字节数（决定了表示的精度）
        :return: (S, N, E) 并且 abs(value) = N * pow(2, E)
        """
        value = value.normalize()
        if value == 0:
            return 0, 0, 0
        s = -1 if value < 0 else 0
        abs_value = abs(value)
        n = int(abs_value)
        frac_part = abs_value - n

        frac_bit_len = max_n_octets * 8 - n.bit_length()
        for i in range(frac_bit_len):
            frac_part *= 2
            if frac_part < 1:
                n <<= 1
            else:
                n = n << 1 + 1
                frac_part -= 1
        e = -1 * frac_bit_len
        while n & 0x01 == 0:
            n >>= 1
            e += 1
        return s, n, e

    @staticmethod
    def decompose_int_to_sne_of_two(value: int):
        s = -1 if value < 0 else 0
        n = abs(value)
        e = 0
        return s, n, e

    @staticmethod
    def decompose_ieee754_to_sne_of_two(value: float, double: bool = True):
        if value == 0:
            return 0, 0, 0
        s = -1 if value < 0 else 0
        if double:
            encoded = struct.pack('>d', value)
            exp = (((encoded[0] & 0x7f) << 4) | ((encoded[1] >> 4) & 0x0f))
            exp = exp - 1023
            n = int.from_bytes(encoded[2:], byteorder='big', signed=False) + ((encoded[1] & 0x0f | 0x10) << 48)
            e = exp - 52
        else:
            encoded = struct.pack('>f', value)
            exp = (((encoded[0] & 0x7f) << 1) | ((encoded[1] >> 7) & 0x01))
            exp = exp - 127
            n = int.from_bytes(encoded[2:], byteorder='big', signed=False) + ((encoded[1] & 0x7f | 0x80) << 16)
            e = exp - 23

        while n & 0x01 == 0:
            n >>= 1
            e += 1
        return s, n, e

    @staticmethod
    def encode_base2(value: Union[Decimal, float, int], base: int, max_n_octets: int = 3):
        assert base in (2, 8, 16)
        data = bytearray()
        first_octet = 0x80  # b8 = 1
        if type(value) == float:
            s, n, e = Real.decompose_ieee754_to_sne_of_two(value)
        else:
            s, n, e = Real.decompose_decimal_to_sne_of_two(value, max_n_octets)
        if s != 0:  # b7 = 1 if s = -1 or 0 otherwise
            first_octet |= 0x40
        if base == 8:  # b6,b5=01
            first_octet |= 0x10
            f = e % 3
            e = e // 3
        elif base == 16:  # b6,b5=10
            first_octet |= 0x20
            f = e % 4
            e = e // 4
        first_octet |= (f << 2)  # b4,b3

        exp_octets = signed_int_to_bytes(e)
        exp_len = len(exp_octets)
        if exp_len == 1:
            data.append(first_octet)
            pass  # b2,b1=00
        elif exp_len == 2:
            data.append(first_octet)
            first_octet |= 0x01  # b2,b1=01
        elif exp_len == 3:
            data.append(first_octet)
            first_octet |= 0x02  # b2,b1=10
        else:
            first_octet |= 0x03  # b2,b1=11
            data.extend(unsigned_int_to_bytes(exp_len))
        data.extend(exp_octets)
        data.extend(unsigned_int_to_bytes(n))
        return data

    @staticmethod
    def encode_base10(value: Union[int, float, Decimal], nr: int = 2):
        assert nr in (1, 2, 3)
        str_value = None
        if nr == 1:
            first_octet = b'\x01'
            str_value = f'{int(value):d}'
        elif nr == 2:
            first_octet = b'\x02'
            if type(value) == int:
                str_value = f'{value:d}'
            elif type(value) == float:
                str_value = f'{value:.15f}'.rstrip('0')
            elif type(value) == Decimal:
                str_value = str(value)
        elif nr == 3:
            first_octet = b'\x03'
            str_value = f'{value:e}'

        return first_octet + str_value.encode('ascii')





