# ASN.1编解码库（Python实现）

遵循X.680/690/696规定，实现常用元素类型的ASN.1的BER/CER/DER解码和DER编码。

## 编码功能 Encoder (encoder.py)

```
from asn1util import *

encoder = Encoder()
with encoder.construct(TagNumber.Sequence):
    encoder.append_primitive(TagNumber.Integer, value=20)
    encoder.append_primitive(TagNumber.Real, value=Decimal('123.456'))
    encoder.append_primitive(TagNumber.Real, value=10.625)
    encoder.append_primitive(TagNumber.OctetString, value=bytes.fromhex('01 03 07') * 50)
    encoder.append_primitive(TagNumber.BitString, value=0xf0f0, bit_length=20)
    encoder.append_primitive(TagNumber.Null, value=None)
    encoder.append_primitive(TagNumber.UTF8String, value='我的世界')
    encoder.append_primitive(TagNumber.NumericString, value='0123456789 ')
    encoder.append_primitive(TagNumber.PrintableString, value='aesWithSha256')
    encoder.append_primitive(TagNumber.ObjectIdentifier, value='1.2.840.113549')

    with encoder.construct(TagNumber.Sequence):
        tz = timezone('Asia/Shanghai')
        dt = tz.localize(datetime.now())
        encoder.append_primitive(TagNumber.GeneralizedTime, value=dt)
        encoder.append_primitive(TagNumber.UTCTime, value=dt)
        encoder.append_primitive(TagNumber.GeneralizedTime, raw='202305032300.1+0800'.encode('utf-8'))

return encoder.data
```

参见test包中的test_tlvs.py。

## 解码功能 Decoder (decoder.py)

### 采用遍历方式
```
from asn1util import *

with open('sm2.rca.der', 'rb') as cert:
    for token in iter(Decoder(cert)):
        pass  # 对token进行操作
```

### 采用Observer模式

```
from asn1util import *
class PrettyPrintObserver(TokenObserver):
    def __init__(self, file=None):
        self._file = file
        print(f'{"T-Off":>8s}{"L-Off":>8s}{"V-Off":>8s}  {"Tag":40s}{"Length":>6s}  {"Value":<s}',
              file=self._file if self._file else sys.stdout)

    """美观打印ASN.1数据的Observer类"""
    def on_event(self, event: str, token: Token, stack: list):
        super().on_event(event, token, stack)
        if event == 'begin' and token.tag.is_primitive:
            return
        if event == 'end' and not token.tag.is_primitive:
            return

        to, lo, vo = token.offsets
        ts = f'{"  " * len(stack)}{str(token.tag)}'
        ls = str(token.length)
        vs = token_value_to_str(token)

        print(f'{to:>8d}{lo:>8d}{vo:>8d}  {ts:40s}{ls:>6s}  {vs:<s}',
              file=self._file if self._file else sys.stdout)


def pretty_print(decoder: Decoder, file = None):
    """通过PrettyPrintObserver类打印ASN.1格式数据"""
    decoder.reset()
    decoder.register_observer(PrettyPrintObserver())

    for token in iter(decoder):
        pass
```

参见asn1util包中decoder.py中的PrettyPrintObserver类和pretty_print函数。

## 主要功能

* tlv.py:       定义了BER-TLV中的Tag，Length，Value
* encoding.py:  定义了较简单的数值和字符串
* real.py:      定义了ASN.1中实数
* oid.py:       定义了Object Identifier
* oid_info.py:  辅助类，用于到http://oid-info.com查询Object Identifier的描述
* util.py:      若干辅助函数
* encoder.py:   编码器
* decoder.py:   解码器
