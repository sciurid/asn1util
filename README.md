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
- asn1util.codec
  - 基于ASN.1编码规则的TLV对象和字节串/流的编解码
- asn1util.exceptions
  - 抛出的异常
- asn1util.util
  - 处理数据的工具
- asn1util.data_types.general_data_types
  - ASN.1元素的基本类型定义：ASN1DataType/ASN1GeneralDataType
  - 基于ASN.1编码规则的ASN.1元素和字节串/流的编解码
- asn1util.data_types.primitive_data_types
  - ASN.1通用类（Universal Class）的基本类型（Primitive Type)元素定义
- asn1util.data_types.constructed_data_types
  - ASN.1通用类（Universal Class）的基本类型（Constructed Type)元素定义
- asn1util.data_types.real
  - ASN.1实数类型（ASN1Real）的处理方法

## 使用

### 下载和安装

```
git clone https://github.com/sciurid/asn1util.git
pip install -e asn1util
```

或者

```
git clone https://gitee.com/LanceChen/asn1.git
pip install -e asn1
```



## 主要参考资料

- X.690: Information technology – ASN.1 encoding rules: Specification of Basic Encoding Rules (BER), 
Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)
- X.680: Information technology – Abstract Syntax Notation One (ASN.1): Specification of basic 
notation
