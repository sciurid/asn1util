from .basic import *


TokenOffsets = NamedTuple('TokenOffsets', t=int, l=int, v=int)
"""标记ASN.1元素各部分偏移值的三元组"""


@dataclass
class Token:
    """标记ASN.1元素各部分的类"""
    tag: Tag  # 元素标签
    length: Length  # 元素长度
    offsets: TokenOffsets  # 元素各部分偏移值
    value: Union[bytes, None]  # 元素值域
    parent: Union['Token', None]  # 父元素
    children: Union[list, None]  # 子元素

    def __str__(self):
        return f'{str(self.tag)} {str(self.length)} ' \
               f'({self.offsets.t:d} {self.offsets.l:d} {self.offsets.v:d}) ' \
               f'{self.value.hex(" ") if self.value else None}'


class DecodingListener:
    """StreamDecoder的解码事件监听器基类

    调用StreamDecoder.add_listener()监听解码事件。
    """

    BEGIN_EVENT: str = 'begin'
    END_EVENT: str = 'end'
    def on_event(self, event: str, token: Token, stack: list):
        """StreamDecoder解析出ASN.1元素的开始和结束时调用

        :param event: 事件类型
        :param token: ASN.1元素节点token
        :param stack: 当前的节点token栈
        """
        assert event in (DecodingListener.BEGIN_EVENT, DecodingListener.END_EVENT)
        raise NotImplementedError()


class StreamDecoder(Iterator):
    """TLV解码器，对数据块或者二进制流进行解码，特别适用于二进制流的情况。

    调用方可以编写TokenObserver的子类，在其中响应asn1元素的'begin’和'end'事件。支持以iteration方式访问。
    注意，迭代访问过程中CONSTRUCTED元素的值均为None，包含关系通过on_event的stack获得。
    """
    def __init__(self, data: Union[bytes, bytearray, BinaryIO]):
        super().__init__()
        self._root_tokens = []  # 根节点（可能是多个）
        self._stack = []  # 节点路径栈
        self._current = None  # 当前正在处理的节点
        self._observers = []  # 事件监听者

        if isinstance(data, bytes):
            self._istream = BytesIO(data)
            self._buffer = data
        elif isinstance(data, bytearray):
            self._istream = BytesIO(data)
            self._buffer = data
        else:
            self._istream = data
            self._buffer = None


    def reset(self):
        self._istream.seek(0)
        self._stack = []
        self._current = None
        self._observers = []
        self._root_tokens = []

    @property
    def root_tokens(self):
        return self._root_tokens

    def add_listener(self, observer: DecodingListener):
        self._observers.append(observer)

    def decode(self):
        while self.proceed_token():
            pass
        return self.root_tokens

    def __next__(self):
        token = self.proceed_token()
        if token:
            return token
        else:
            raise StopIteration

    def proceed_token(self) -> Optional[Token]:
        """处理遇到的下一个元素
        """
        tof = self._istream.tell()  # 标签Tag域的偏移值
        tag = Tag.decode(self._istream)  # 读取标签
        if tag is None:  # 遇到字节流结尾，读取结束
            if self._stack:  # 如果此时栈不为空，则说明父元素未读取结束
                raise InvalidEncoding(f"数据截断导致父元素不完整/Incomplete parent item due to data truncation: "
                                      f"{self._stack[-1]}")
            return None

        lof = self._istream.tell()  # 长度Length域的偏移值
        length = Length.decode(self._istream)  # 读取长度
        if length is None:  # 标签后无长度，说明编码错误或者数据不完整
            raise InvalidEncoding(f'标签后无长度，编码错误或者数据不完整'
                                  f'/Missing length due to invalid encoding or data truncation: '
                                  f'{self._stack[-1]} > {tag}')

        vof = self._istream.tell()  # 数值Value域的偏移值
        self._current = Token(tag, length, TokenOffsets(tof, lof, vof), None, None, None)  # 当前标签读出
        if self._stack:  # 当前层级非顶级，将当前Token加入上级Constructed
            self._current.parent = self._stack[-1]
            self._stack[-1].children.append(self._current)
        else:  # 当前层级为顶级，将当前Token加入self._roots
            self._root_tokens.append(self._current)
        self._on_token_begin()  # 触发开始事件

        if tag.is_primitive:  # 基本类型元素
            self._proceed_primitive()  # 处理基本类型元素本身
            ret = self._current  # 保留当前元素用于返回
            # self._check_to_accomplish_constructed()在结束父元素时会将self._current设置为父元素
            self._check_to_end_constructed()  # 检查是否可以结束父元素
            return ret
        else:
            self._begin_proceed_constructed()  # 处理组合类型元素
            return self._current

    def _proceed_primitive(self):
        """处理基本类型元素"""
        if not self._current.length.is_definite:  # 基本类型元素必须为定长
            raise InvalidEncoding(f"基本类型元素长度为不定长/Primitive tag with indefinite length: {self._current}")

        the_length = self._current.length.value
        value_octets = self._istream.read(the_length)  # 读取数值Value域
        if len(value_octets) < the_length:  # 剩余字节不足
            raise InvalidEncoding(f"数据域长度不足/Incomplete value field: {self._current}")
        # if self._buffer:
        #     pos = self._current.offsets.v
        #     end = self._current.offsets.v + self._current.length.octets
        #     self._current.octets = self._buffer[pos:end]
        # else:
        #     self._current.octets = value_octets
        self._current.value = value_octets
        self._on_token_end()  # 触发基本元素结束事件

    def _begin_proceed_constructed(self):
        """开始处理组合类型元素"""
        self._current.children = []  # 初始化子节点列表
        self._stack.append(self._current)  # 将当前节点入栈

    def _check_to_end_constructed(self):
        """检查是否可以结束组合类型元素，在每个基本元素处理完毕后调用"""
        while self._stack:  # 检查是否存在父元素
            parent = self._stack[-1]  # 取得父元素
            if parent.length.is_definite:  # 父元素定长
                expected_pos = parent.offsets.v + parent.length.value
                # 根据父元素长度Length域值和Value域偏移值计算父元素结束偏移值
                current_pos = self._istream.tell()  # 当前元素结束时的偏移值
                if expected_pos == current_pos:  # 相等则父元素也结束，退栈
                    self._current = self._stack.pop()  # 当前元素设置为父元素
                    self._on_token_end()  # 触发父元素结束事件
                elif current_pos > expected_pos:  # 当前位置超出父元素数值域边界，格式错误
                    raise InvalidEncoding("元素结束位置{0:d}超出上级元素边界{1:d}"
                                          "/Ending position {0:d}exceeds expected position {1:d}:"
                                          "{2}>{3}".format(current_pos, expected_pos,
                                                           self._stack[-1], self._current))
                else:  # 父元素尚未结束
                    break
            else:  # 父元素为不定长元素
                # 如果当前是EOC标记，则父元素结束
                if self._current.tag.octets == b'\x00':
                    if self._current.length != 0:
                        raise InvalidEncoding('内容结束EOC元素的长度不为0/Length of End-of-content is not 0')
                    self._current = self._stack.pop()  # 退栈并将父元素设置为当前元素
                    self._on_token_end()  # 触发父元素结束事件
                else:  # 父元素尚未结束
                    break

    def _on_token_begin(self):
        """触发元素开始事件"""
        logger.debug(f'->{"  " * len(self._stack)} {self._current}')
        for obs in self._observers:
            obs.on_event(DecodingListener.BEGIN_EVENT, self._current, self._stack)

    def _on_token_end(self):
        """触发元素结束事件"""
        logger.debug(f'<-{"  " * len(self._stack)} {self._current}')
        for obs in self._observers:
            obs.on_event(DecodingListener.END_EVENT, self._current, self._stack)


