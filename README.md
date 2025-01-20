# ASN.1编解码工具（asn1util）

根据X.680/690/696规定，实现ASN.1的编解码和部分数据类型处理的纯Pyhon库。

- BER解码
- DER解码编码
- 部分通用类（Universal Class）数据类型格式处理

## 介绍

抽象语法标记（版本1）ASN.1 (Abstract Syntax Notation One)是由国际电信联盟（ITU）下属的
电信和信息通信技术标准化部门（ITU-T）推荐的用户表示信息数据语法的编码格式。

ASN.1格式定义多种基本的数据元素类型和结构类型，以及基本编码规则（Basic Encoding Rule, BER）、
规范编码规则（Canonical Encoding Rule, CER）和区分编码规则（Distinguished Encoding Rule, DER）
三种编码规则。其中BER规则最为宽松，典型应用如在智能卡领域中；DER规则最为严格，可以确保编码的一致性，
典型应用在数字证书等密码学相关领域。

### 主要模块和相应功能

- asn1util.tlv
  - Tag和Length的定义，实现了编码语法规则
- asn1util.exceptions
  - 抛出的异常
- asn1util.util
  - 处理数据的工具
- asn1util.codec.basic
  - 基于ASN.1编码规则的TLV对象和字节串/流的基本编解码函数
- asn1util.codec.decoder
  - 基于ASN.1编码规则的流式输出的解码类
- asn1util.codec.encoder
  - 基于ASN.1编码规则的流式输出的编码类
- asn1util.data_types.general_data_types
  - ASN.1元素的基本类型定义：ASN1DataType/ASN1GeneralDataType
  - 基于ASN.1编码规则的ASN.1元素和字节串/流的编解码
- asn1util.data_types.primitive_data_types
  - ASN.1通用类（Universal Class）的基本类型（Primitive Type)元素定义
- asn1util.data_types.constructed_data_types
  - ASN.1通用类（Universal Class）的基本类型（Constructed Type)元素定义
- asn1util.data_types.real
  - ASN.1实数类型（ASN1Real）的处理方法

## 下载和安装

```
git clone https://github.com/sciurid/asn1util.git
pip install -e asn1util
```

或者

```
git clone https://gitee.com/LanceChen/asn1.git
pip install -e asn1
```

## 快速使用

### ASN.1基本数据类型编码

```
a = ASN1Integer(1234567890)  # 整数
print(a, a.octets.hex())

b = ASN1Real(1.2345678)  # 实数（二进制浮点数）
c = ASN1Real(Decimal('1.2345678'))  # 实数（十进制浮点数）
print(b, c)
d = ASN1Real(12345678, base=2)  # 实数（二进制整数）
print(d, d.octets.hex())
e = ASN1Real(12345678)  # 实数（十进制整数）
print(e, e.octets.hex())

# 文本的各种编码格式
f = ASN1PrintableString('A fox jumps over a lazy dog.')  # ISO-8859-1
print(f, f.octets.hex(), f.value)
g = ASN1UTF8String('中华人民共和国万岁 世界人民大团结万岁')  # UTF-8
h = ASN1UniversalString('中华人民共和国万岁 世界人民大团结万岁')  # UTF-32BE (UCS-4)
i = ASN1BMPString('中华人民共和国万岁 世界人民大团结万岁')  # UTF-16BE (UCS-2)
print(g, g.octets.hex(), g.value)
print(h, h.octets.hex(), h.value)
print(i, i.octets.hex(), i.value)

j = ASN1ObjectIdentifier('1.2.840.113549.1.1.11')  # OID
print(j)

k = ASN1OctetString(bytes.fromhex('00 01 02 03 04 05 06 07 08'))  # 字节串
print(k, k.octets.hex())
l = ASN1BitString((bytes.fromhex('00 01 02 03 04 05 06 07 08'), 4))  # 比特串，注意末尾的未用比特数
print(l, l.octets.hex())

now = datetime.now().astimezone(timezone.utc)
m = ASN1GeneralizedTime(now)  # 通用时间
print(m, m.octets)
n = ASN1UTCTime(now)  # UTC时间
print(n, n.octets)

```

### ASN.1组合数据类型编码

#### 层次构造

使用StreamEncoder类来进行各种嵌套层次的构建。

```
from asn1util import *
encoder = StreamEncoder()
with encoder.construct(TAG_Sequence):
    encoder.append_primitive(TAG_Boolean, b'\xff')
    encoder.append_primitive(TAG_Integer, b'\x01\x02\x03\x04')
    encoder.append_primitive(TAG_UTF8String, '中华人民共和国万岁 世界人民大团结万岁'.encode('utf-8'))
    with encoder.construct(TAG_Sequence):
        encoder.append_primitive(TAG_Boolean, b'\x00')
        encoder.append_primitive(TAG_PrintableString, 'The fox jumps over a lazy dog.'.encode('ascii'))
print(encoder.data.hex(' '))

for t, l, v in iter_descendant_tlvs(encoder.data, in_octets=False):
    print(t, l, v.hex())

asn1_print_data(encoder.data)
```

#### 支持直接编码Python基本数据类型

```
encoder = StreamEncoder()
with encoder.within_sequence():
    encoder.append_boolean(True)
    encoder.append_integer(32767)
    encoder.append_integer(-32768)

with encoder.within_set():
    encoder.append_real(1234567890)
    encoder.append_real(Decimal(1234567890))
    encoder.append_real(1.23456789)
    encoder.append_real(1.23456789, base=10)

with encoder.within_sequence():
    encoder.append_utf8_string('中华人民共和国万岁 世界人民大团结万岁')
    encoder.append_printable_string('The fox jumps over a lazy dog. (1234567890)')
    encoder.append_object_identifier('1.2.840.113549.1.1.11')

print(encoder.data.hex(' '))
for t, l, v in iter_descendant_tlvs(encoder.data, return_octets=False):
    print(t, l, v.hex())
asn1_print_data(encoder.data)
```

#### 支持不定长（Indefinite Length）

注：不定长组合元素不符合DER规范，较为少见。

```
from asn1util import *
encoder = StreamEncoder()
with encoder.construct(TAG_Sequence, True):
    encoder.append_primitive(TAG_Boolean, b'\xff')
    encoder.append_primitive(TAG_Integer, b'\x01\x02\x03\x04')
    encoder.append_primitive(TAG_UTF8String, '中华人民共和国万岁 世界人民大团结万岁'.encode('utf-8'))
    with encoder.construct(TAG_Sequence, True):
        encoder.append_primitive(TAG_Boolean, b'\x00')
        encoder.append_primitive(TAG_PrintableString, 'The fox jumps over a lazy dog.'.encode('ascii'))
print(encoder.data.hex(' '))

for t, l, v in iter_descendant_tlvs(encoder.data, in_octets=False):
    print(t, l, v.hex())

asn1_print_data(encoder.data)
```

### ASN.1解码

#### 简单解码

- read_next_tlv 从字符流中读取下一个TLV
- iter_tlvs 遍历当前层次的TLV，组合元素视为本层的单个TLV
- iter_descendant_tlvs 以深度遍历方式遍历所有TLV

```
encoder = StreamEncoder()
encoder.append_primitive(TAG_Integer, b'\x01\x02\x03\x04')
with encoder.construct(TAG_Sequence):
    encoder.append_primitive(TAG_Boolean, b'\x00')
    encoder.append_primitive(TAG_PrintableString, 'The fox jumps over a lazy dog.'.encode('ascii'))

print(encoder.data.hex(' '))
for t, l, v in iter_tlvs(encoder.data, return_octets=False):
    print(t, l, v.hex())

print(encoder.data.hex(' '))
for t, l, v in iter_descendant_tlvs(encoder.data, return_octets=False):
    print(t, l, v.hex())

print(encoder.data.hex(' '))
stream = BytesIO(encoder.data)
t, l, v = read_next_tlv(stream, return_octets=True)
print(t.hex(), l.hex(), v.hex())
t, l, v = read_next_tlv(stream, return_octets=True)
print(t.hex(), l.hex(), v.hex())
t, l, v = read_next_tlv(stream, return_octets=True)
self.assertIsNone(t)
self.assertIsNone(l)
self.assertIsNone(v)
```

## 后续开发计划

- 扩充常见的ASN.1类型
- 增加默认类型的StreamEncoder类或者方法

## 主要参考资料

- X.690: Information technology – ASN.1 encoding rules: Specification of Basic Encoding Rules (BER), 
Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)
- X.680: Information technology – Abstract Syntax Notation One (ASN.1): Specification of basic 
notation
