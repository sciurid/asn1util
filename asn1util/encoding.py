from datetime import *

from typing import Union
import isodate
from isodate.duration import Duration
import re
import chardet
from .tlv import Value, UnsupportedValueException, ValueEncodingException


class BooleanValue:
    @staticmethod
    def encode(value: Union[bool, int]) -> bytes:
        if isinstance(value, bool):
            return b'\xff' if value else b'\x00'
        if isinstance(value, int):
            return b'\xff' if value != 0 else b'\x00'
        raise UnsupportedValueException(value)

    @staticmethod
    def decode(value: bytes) -> bool:
        if len(value) != 1:
            raise UnsupportedValueException(value)
        return value[0] != 0


class BitString(Value):
    def __init__(self, octets: bytes):
        super().__init__(octets)
        initial = self._octets[0]
        if initial > 7:
            raise ValueEncodingException(f'BitString未用比特数为{initial}/ Unused {initial} bits in BitString')
        self._bit_length = (len(self._octets) - 1) * 8 - initial
        if self._bit_length < 0:
            raise ValueEncodingException(f'BitString为空但未用比特数为{initial}/ Unused {initial} bits in empty BitString.')
        self._value = int.from_bytes(self._octets[1:], byteorder='big', signed=False)
        self._value >>= initial

    def __str__(self):
        return f'{{:0{self._bit_length}b}}'.format(self._value)

    @staticmethod
    def decode(octets: bytes) -> 'BitString':
        return BitString(octets)

    @staticmethod
    def encode(value: int, bit_length: int = None) -> bytes:
        if bit_length == 0:  # 空串
            assert value == 0
            return bytes((0x00, ))

        assert 0 <= value < (0x01 << bit_length)  # 比特长度足以容纳数值

        byte_length = (bit_length + 7) // 8
        unused_bits = byte_length * 8 - bit_length

        octets = bytearray((unused_bits, ))
        octets.extend((value << unused_bits).to_bytes(byte_length, byteorder='big', signed=False))
        return bytes(octets)


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


_YEAR_G = r'(?P<year>[0-9]{4})'
_YEAR_U = r'(?P<year>[0-9]{2})'
_MONTH = r'(?P<month>0[1-9]|1[0-2])'
_DAY = r'(?P<day>[0-2][0-9]|3[01])'
_HOUR = r'(?P<hour>[01][0-9]|2[0-3])'
_MINUTE = r'(?P<minute>[0-5][0-9])'
_SECOND = r'(?P<second>[0-5][0-9])'
_FRACTION = r'(?P<fraction>\.[0-9]+)'
_TIMEZONE = r'(?P<timezone>Z|(?P<tzsign>[+-])(?P<tzhour>0[0-9]|1[0-2])(?P<tzminute>[0-5][0-9])?)'


class GeneralizedTime(Value):
    DATETIME_PATTERN = re.compile(f'^{_YEAR_G}{_MONTH}{_DAY}{_HOUR}{_MINUTE}?{_SECOND}?{_FRACTION}?{_TIMEZONE}?$')

    def __init__(self, octets: bytes):
        super().__init__(octets)

        dt_str = octets.decode('utf-8')
        m = GeneralizedTime.DATETIME_PATTERN.match(dt_str)
        if m is None:
            raise UnsupportedValueException(f"Generalized Time: {dt_str}")

        year, month, day, hour, minute, second, fraction, tz, tzsign, tzhour, tzminute = m.groups()
        if fraction:
            if second is None:
                if minute is None:
                    frac_delta = timedelta(hours=float(fraction))
                else:
                    frac_delta = timedelta(minutes=float(fraction))
            else:
                frac_delta = timedelta(seconds=float(fraction))
        else:
            frac_delta = None

        if tz == 'Z':
            tz_delta = None
        else:
            tz_delta = timedelta(hours=int(tzhour) if tzhour else 0,
                                 minutes=int(tzminute) if tzminute else 0) * (1 if tzsign == '-' else -1)

        self._value = datetime(year=int(year), month=int(month), day=int(day),
                               hour=int(hour), minute=int(minute) if minute else 0,
                               second=int(second) if second else 0)
        if frac_delta:
            self._value += frac_delta
        if tz_delta:
            self._value += tz_delta

    def __str__(self):
        return self._value.strftime('UTC %Y-%m-%d %H:%M:%S.%f')

    @staticmethod
    def encode(value: datetime) -> bytes:
        if value.tzinfo:
            value = value.astimezone(timezone.utc)
        if value.microsecond == 0:
            res = value.strftime("%Y%m%d%H%M%SZ")
        else:
            res = value.strftime("%Y%m%d%H%M%S.%fZ")
        return res.encode('utf-8')

    @staticmethod
    def decode(octets: bytes):
        return GeneralizedTime(octets)


class UTCTime(Value):
    DATETIME_PATTERN = re.compile(f'^{_YEAR_U}{_MONTH}{_DAY}{_HOUR}{_MINUTE}{_SECOND}?{_TIMEZONE}$')

    def __init__(self, octets: bytes):
        super().__init__(octets)

        dt_str = octets.decode('utf-8')
        m = UTCTime.DATETIME_PATTERN.match(dt_str)
        if m is None:
            raise UnsupportedValueException(f"UTC Time: {dt_str}")

        year, month, day, hour, minute, second, tz, tzsign, tzhour, tzminute = m.groups()

        if tz == 'Z':
            tz_delta = None
        else:
            tz_delta = timedelta(hours=int(tzhour) if tzhour else 0,
                                 minutes=int(tzminute) if tzminute else 0) * (1 if tzsign == '-' else -1)

        self._value = datetime(year=int(2000 + int(year) if int(year) < 70 else 1900 + int(year)),
                               month=int(month), day=int(day),
                               hour=int(hour), minute=int(minute),
                               second=int(second) if second else 0)
        if tz_delta:
            self._value += tz_delta

    def __str__(self):
        return self._value.strftime('UTC %Y-%m-%d %H:%M:%S')

    @staticmethod
    def decode(octets: bytes):
        return UTCTime(octets)

    @staticmethod
    def encode(value: datetime):
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc)
        return value.strftime('%y%m%d%H%M%SZ').encode('utf-8')


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
    return isodate.duration_isoformat(value).lstrip('P').build('ascii')


def decode_duration(value: bytes) -> timedelta:
    res = isodate.parse_duration('P' + value.decode('ascii'))
    if isinstance(Duration):
        return res.totimedelta()
    else:
        return res
