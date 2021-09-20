from datetime import *
import isodate
import re


def encode_bit_string(octets: bytes, bit_length: int = None):
    if bit_length is None:
        bit_length = len(octets) * 8
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


def decode_bit_string(octets: bytes) -> (bytes, int):
    bit_length = (len(octets) - 1) * 8
    if octets[0] > 0:
        bit_length -= octets[0]
    return octets[1:], bit_length


PATTERN_BMP_STRING = re.compile(r'^[\u0000-\uffff]*$')


def encode_bmp_string(value: str) -> bytes:
    assert PATTERN_BMP_STRING.match(value) is not None
    return value.encode('utf-16')


def encode_generalized_time(value: datetime, spec='auto') -> bytes:
    return value.isoformat(timespec=spec).encode('ascii')


def encode_utc_time(value: datetime, spec='auto') -> bytes:
    return (value.astimezone(timezone.utc).isoformat(timespec=spec).rstrip('+00:00') + 'Z').encode('ascii')


def encode_time(value: time, spec='auto') -> bytes:
    assert isinstance(value, time)
    return value.isoformat(timespec=spec).encode('ascii')


def encode_date(value: date) -> bytes:
    if isinstance(value, datetime):
        value = date(value.year, value.month, value.day)
    assert isinstance(value, date)
    return value.isoformat().encode('ascii')


def encode_duration(value: timedelta) -> bytes:
    assert isinstance(value, timedelta)
    return isodate.duration_isoformat(value).encode('ascii')
