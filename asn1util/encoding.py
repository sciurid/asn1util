from datetime import *
from typing import Union
import isodate
from isodate.duration import Duration
import re
import chardet
from .util import *


class NotSupportedValueException(ASN1EncodingException):
    def __init__(self, value):
        self.message = f'Value {value} of type {type(value)} is not supported.'


class BooleanValue:

    @staticmethod
    def encode(value: Union[bool, int]):
        if isinstance(value, bool):
            return b'\xff' if value else b'\x00'
        if isinstance(value, int):
            return b'\xff' if value != 0 else b'\x00'
        raise NotSupportedValueException(value)

    @staticmethod
    def decode(value: bytes):
        if len(value) != 1:
            raise NotSupportedValueException(value)
        return value[0] != 0


class BitString:
    def __init__(self, octets: bytes, bit_length: int):
        assert octets is not None
        if bit_length is None:
            bit_length = len(octets) * 8
            self._unused = 0
        else:
            assert (len(octets) - 1) * 8 < bit_length <= len(octets) * 8
            self._unused = 0 if bit_length % 8 == 0 else 8 - (bit_length % 8)

        self._octets = octets
        self._bit_length = bit_length

    def __repr__(self):
        if self._unused == 0:
            header = '[{:d} bytes] '.format(len(self._octets))
        else:
            header = '[{:d} bytes with last {:d} bits unused] '.format(self._bit_length, self._unused)
        return header + self._octets.hex(' ')

    @staticmethod
    def encode(octets: bytes, bit_length: int = None):
        bs = BitString(octets, bit_length)
        encoded = bytearray()
        encoded.append(bs._unused)
        encoded.extend(bs._octets)
        encoded[-1] &= ((0xff << bs._unused) & 0xff)
        return encoded

    @staticmethod
    def decode(octets: bytes) -> (bytes, int):
        bit_length = (len(octets) - 1) * 8
        if octets[0] > 0:
            bit_length -= octets[0]
        return BitString(octets[1:], bit_length)


def encode_restricted_string(value: str, encoding="iso-8859-1") -> bytes:
    return value.encode(encoding=encoding)


def decode_restricted_string(value: bytes, encoding=None) -> str:
    if encoding is None:
        charset = chardet.detect(value)
        if charset['confidence'] >= 0.5:
            return value.decode(encoding=charset['encoding'])
        else:
            return value.hex()
    else:
        return value.decode(encoding=encoding)


PATTERN_BMP_STRING = re.compile(r'^[\u0000-\uffff]*$')


def encode_bmp_string(value: str) -> bytes:
    assert PATTERN_BMP_STRING.match(value) is not None
    return value.encode('utf-16')


class GeneralizedTime:
    DATETIME_PATTERN = re.compile(r'^(?:([0-9]{4})(0[1-9]|1[0-2])([0-2][0-9]|3[01]))'
                                  r'([01][0-9]|2[0-3])(?:([0-5][0-9])([0-5][0-9])?)?(\.[0-9]+)'
                                  r'(Z|([+-])(0[0-9]|1[0-2])([0-5][0-9])?)?$')

    @staticmethod
    def encode(dt: datetime) -> bytes:
        if dt.tzinfo is None:
            if dt.microsecond == 0:
                res = dt.strftime('%Y%m%d%H%M%S')
            else:
                res = dt.strftime('%Y%m%d%H%M%S%f')
        else:
            if dt.microsecond == 0:
                res = dt.strftime('%Y%m%d%H%M%S%z')
            else:
                res = dt.strftime('%Y%m%d%H%M%S%f%z')
        return res.encode('utf-8')

    @staticmethod
    def decode(value: bytes):
        dt_str = value.decode('utf-8')
        m = GeneralizedTime.DATETIME_PATTERN.match(dt_str)
        if m is None:
            raise NotSupportedValueException(f"Generalized Time: {dt_str}")
        else:
            year = m.group(1)
            month = m.group(2)
            day = m.group(3)
            hour = m.group(4)
            minute = m.group(5)
            second = m.group(6)
            frac = m.group(7)
            if second is None:
                if minute is None:
                    frac_delta = timedelta(hours=float(frac))
                    minute = '00'
                else:
                    frac_delta = timedelta(minutes=float(frac))
                second = '00'
            else:
                frac_delta = timedelta(seconds=float(frac))

            string_datetime = year + month + day + hour + minute + second

            tz = m.group(8)
            if tz is None:
                dtf = '%Y%m%d%H%M%S'
            else:
                dtf = '%Y%m%d%H%M%S%z'
                if tz == 'Z':
                    string_datetime += '+0000'
                else:
                    tzsign = m.group(9)
                    tzhour = m.group(10)
                    tzminute = m.group(11)
                    string_datetime += tzsign + tzhour + ('00' if tzminute is None else tzminute)

            dt = datetime.strptime(string_datetime, dtf)
            dt += frac_delta
            return dt


class UTCTime:
    UTC_TIME_PATTERN = re.compile(
        r'^(?:([0-9]{2})(0[1-9]|1[0-2])([0-2][0-9]|3[01]))'
        r'([01][0-9]|2[0-3])([0-5][0-9])([0-5][0-9])?'
        r'(Z|[+-](?:0[0-9]|1[0-2])[0-5][0-9])$')

    @staticmethod
    def decode(value: bytes):
        dt_str = value.decode('utf-8')
        m = UTCTime.UTC_TIME_PATTERN.match(dt_str)
        if m is None:
            raise NotSupportedValueException(f"Generalized Time: {dt_str}")
        else:
            year = m.group(1)
            month = m.group(2)
            day = m.group(3)
            hour = m.group(4)
            minute = m.group(5)
            second = m.group(6)
            tz = m.group(7)
            if second is None:
                second = '00'

            if tz == 'Z':
                tz = '+0000'
            dt = datetime.strptime(year + month + day + hour + minute + second + tz, '%y%m%d%H%M%S%z')
            return dt

    @staticmethod
    def encode(dt: datetime):
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc)
        return dt.strftime('%y%m%d%H%M%SZ')


def encode_time(value: time, spec='auto') -> bytes:
    assert isinstance(value, time)
    return value.isoformat(timespec=spec).encode('ascii')


def encode_date(value: Union[date, datetime]) -> bytes:
    if isinstance(value, datetime):
        value = date(value.year, value.month, value.day)
    assert isinstance(value, date)
    return value.isoformat().encode('ascii')


def encode_duration(value: timedelta) -> bytes:
    assert isinstance(value, timedelta)
    return isodate.duration_isoformat(value).lstrip('P').encode('ascii')


def decode_duration(value: bytes) -> timedelta:
    res = isodate.parse_duration('P' + value.decode('ascii'))
    if isinstance(Duration):
        return res.totimedelta()
    else:
        return res
