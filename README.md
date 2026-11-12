# TLM1 不可信遥测增量解析器

一个仅依赖 Python 3.11+ 标准库的 TLM1 二进制协议解析库。它面向不可信输入，采用显式容器栈、流式字段消费、声明长度即时校验和可配置逻辑限额，重点防止恶意长度、深嵌套和碎片输入造成无界缓冲、重复扫描或递归耗尽。

## 运行全部确定性测试

在仓库根目录执行：

```bash
python3 -m unittest discover -s tests -t . -v
```

该命令包含单元回归测试和固定随机种子的结构生成/字节变异模糊测试。模糊测试固定为 3,000 个用例、三种分片方案，并设有 50 秒 watchdog；正常环境应显著早于 60 秒结束。运行不访问网络，不读写真实用户文件；只有发现失败时才向仓库内的 `artifacts/fuzz_failures/` 写入重放记录。

## 协议

所有多字节整数均为大端序。帧头固定 12 字节：

| 偏移 | 长度 | 字段 | 要求 |
| ---: | ---: | --- | --- |
| 0 | 4 | 魔数 | ASCII `TLM1` |
| 4 | 1 | 版本 | 必须为 `1` |
| 5 | 1 | flags | 必须为 `0` |
| 6 | 2 | 保留字段 | 必须为 `0` |
| 8 | 4 | 正文长度 | 无符号 32 位，满足配置上限 |

正文是连续的 TLV 节点序列，每个节点由 1 字节类型、4 字节无符号值长度和对应值组成。类型 `0x10` 是容器，其值必须恰好完整解析为子 TLV 序列；其他类型是保留原始类型和值的字节串。空正文、空容器和空字节串均合法。容器内部不允许存在无法构成完整 TLV 头的尾部字节。

顶层节点深度为 1。容器子节点深度加 1；空容器也消耗一个节点计数和其所在深度。

## API

```python
from tlm_parser import (
    FinishStatus,
    FrameParser,
    ParserLimits,
    ParseStatus,
)

parser = FrameParser(
    ParserLimits(
        max_frame_body=64 * 1024,
        max_value_bytes=16 * 1024,
        max_nodes=1024,
        max_depth=16,
        max_pending_bytes=16 * 1024,
    )
)

pending = memoryview(input_bytes)
while True:
    result = parser.feed(pending)
    if result.status is ParseStatus.FRAME_READY:
        consume_frame(result.frame)
        pending = pending[result.consumed :]
        if not pending:
            break
        continue
    if result.status is ParseStatus.NEED_MORE:
        # NEED_MORE 总是消费本次输入中的全部字节。
        break
    if result.status is ParseStatus.FAILED:
        report_error(result.error.code, result.error.offset)
        parser.reset()
        break

finish = parser.finish()
if finish.status is FinishStatus.CLEAN_END:
    pass  # 输入恰好在帧边界结束
else:
    report_error(finish.error.code, finish.error.offset)
    parser.reset()
```

`feed()` 接受 `bytes`、`bytearray` 或连续的一维字节 `memoryview`。二维、非连续或 item size 不等于 1 的 `memoryview` 会被拒绝。错误的 Python 调用类型会抛出 `TypeError`/`ValueError`；这是调用方编程错误，不是协议拒绝。

### 状态与消费语义

每次 `feed()` 最多交付一个完整帧：

| 状态 | `consumed` | 含义 |
| --- | --- | --- |
| `NEED_MORE` | 等于本次输入长度 | 所有输入字节已被消费，尚无完整帧；继续提供后续输入。空输入也返回此状态。 |
| `FRAME_READY` | 当前帧实际占用字节数 | 返回一个已完全校验的帧。`consumed` 之后可能还有下一帧，调用方必须再次传入剩余数据。 |
| `FAILED` | 本次调用已经消费的字节数 | 返回稳定的 `ParserError`。解析器进入终态，必须调用 `reset()` 才能复用。 |

对包含多个帧的输入，每次调用停在第一个帧的精确边界，不解析也不复制后续帧。`feed()` 不会为后续调用保留调用方视图或可变缓冲区。

状态转换：

```text
HEADER --完整合法帧头--> BODY --正文完整且全部校验--> FRAME_READY --> HEADER
HEADER/BODY --协议拒绝--> FAILED --reset()--> HEADER
HEADER --finish() 且头部不完整--> FAILED(TRUNCATED_HEADER) --reset()--> HEADER
BODY   --finish() 且正文不完整--> FAILED(TRUNCATED_BODY)   --reset()--> HEADER
HEADER --finish() 且恰在帧边界--> CLEAN_END
```

`finish()` 在干净边界返回 `CLEAN_END`，此时解析器仍可继续接收新帧。若存在半个帧头或未完成正文，返回 `FAILED`，错误类别分别为 `TRUNCATED_HEADER` 或 `TRUNCATED_BODY`；失败后也必须 `reset()`。`reset()` 清除失败状态、半帧状态、暂存值和累计工作量计数。

### 结果对象

```python
TlvNode(node_type: int, is_container: bool, value: bytes | tuple[TlvNode, ...])
ParsedFrame(body_length: int, nodes: tuple[TlvNode, ...])
```

不透明节点的值是解析器新创建的 `bytes`；容器节点的值是由子节点组成的 `tuple`。调用方之后修改原 `bytearray`、释放原 `memoryview` 或调用 `reset()`，均不会改变已交付帧。

## 资源限制

| 配置项 | 默认值 | 限制对象 | 何时拒绝 |
| --- | ---: | --- | --- |
| `max_frame_body` | 1 MiB | 帧头声明的正文协议字节数 | 读完 12 字节帧头后立即 |
| `max_value_bytes` | 256 KiB | 任意节点声明的值协议字节数（含容器字节范围） | 读完 5 字节节点头后立即 |
| `max_nodes` | 4096 | 节点 Python 对象计数，空容器也计数 | 新节点头可判定时立即 |
| `max_depth` | 32 | 嵌套深度，顶层为 1，空容器也占深度 | 新节点头可判定时立即；深度上限处的非空容器也会提前拒绝 |
| `max_pending_bytes` | 256 KiB | 单个尚未完成的不透明值的暂存字节数 | 不透明节点头可判定时立即 |

所有值都必须恰好达到限制才允许通过；限制值本身允许，超出 1 字节即拒绝。测试覆盖限制内、恰好达到和超出一字节三种情况。

`max_pending_bytes` 不是“整个帧缓冲”或“容器正文缓冲”上限：容器正文始终流式解析，不先汇总成一个缓冲区。它限制单个不完整不透明值的暂存。帧头和节点头分别使用至多 12 和 5 字节的固定临时区。已完成的合法节点仍需保存在结果中，直到整帧交付；该输出量受 `max_frame_body`、`max_value_bytes` 和 `max_nodes` 约束。

这些限制是协议字节量、节点对象数、深度和暂存量的逻辑上限，不是整个 Python 进程的精确内存上限，也没有计入解释器对象头、分配器碎片、调用栈、结果 tuple 和调用方自身输入所占内存。部署时仍应在外层设置进程内存、输入速率和连接级总量限制。

## 错误类别与位置

失败类别是稳定的字符串枚举：

- `BAD_MAGIC`, `UNSUPPORTED_VERSION`, `NONZERO_FLAGS`, `NONZERO_RESERVED`
- `FRAME_TOO_LARGE`, `VALUE_TOO_LARGE`, `STAGING_LIMIT`
- `TOO_MANY_NODES`, `DEPTH_EXCEEDED`
- `MALFORMED_TLV`：值越过父容器边界、容器尾部不足 5 字节、非空容器值不足 5 字节等结构错误
- `TRUNCATED_HEADER`, `TRUNCATED_BODY`

`ParserError.offset` 是从最近一次 `reset()` 起算的绝对零基字节位置，不随分片方式变化。约定如下：

- 帧头字段错误位于对应字段起点；正文长度超限位于长度字段起点（帧头偏移 8）。
- 节点头导致的限制、边界、计数和深度错误位于该节点类型字节起点。
- 容器内不可解析尾部位于第一个无法构成新节点头的字节。
- 截断错误位于期望但尚未到达的下一个字节位置。

同一输入在相同限制下，无论一次传入、逐字节传入还是随机分片，帧输出、错误类别和全局 `offset` 都应一致。回归测试和模糊测试均直接比较这些属性。

节点头的检查优先级固定为：单值长度上限、`max_pending_bytes`（仅不透明节点）、父容器边界、节点总数、当前节点深度，然后是非空容器的子深度和最小可解析长度。这样可以确保恶意声明长度一旦可判定就立即拒绝。

## 资源耗尽防护策略

1. 不在正文级缓冲整帧。帧头完成后直接流式解析 TLV；容器只保存显式栈上下文和已完成的子节点。
2. 不按攻击者声明长度预先分配大缓冲区。不透明值只随实际到达字节增长；发现声明值超限时，在值数据到达前拒绝。
3. 容器和嵌套使用显式 `list` 栈，不使用 Python 递归。测试在较低递归上限下解析 300 层嵌套。
4. `NEED_MORE` 总是消费全部输入，调用方只重新传入 `FRAME_READY` 或 `FAILED` 场景下未消费的尾部；已经解析的字节不会被再次扫描。逐字节输入产生逐字节调用开销，但每个字节只按一次单调流程处理。
5. 每个节点头只解码一次，每个容器上下文只入栈/出栈一次，每个不透明负载字节只逻辑保留一次。随机分片不会重新解析历史。
6. 结果中的字节来自解析器自建 `bytes`，不引用调用方可变缓冲区；`feed()` 返回前也不会长期保存输入视图。

`FrameParser.stats` 提供可重复的工作量证据：

- `bytes_consumed`：实际消费的输入字节数；
- `frame_headers_decoded`、`node_headers_decoded`：头解码次数；
- `payload_bytes_copied`：逻辑保留的不透明负载字节数；
- `staging_appends`：暂存追加次数，随分片变化；
- `staging_bytes_high_water`：观察到的不完整不透明值暂存高水位，不应超过 `max_pending_bytes`；
- `max_container_stack_depth`：观察到的最大容器栈深度。

测试对同一帧分别使用整段、逐字节和随机分片，断言 `bytes_consumed`、帧头/节点头解码次数和负载字节数完全一致，且负载字节数不超过消费字节数。这不依赖一次耗时测量，也不宣称分配器层面的精确复杂度证明。

## 测试与固定种子模糊测试

`tests/test_protocol.py` 覆盖正常嵌套、空正文/空容器/空值、多帧、逐字节和随机分片、三种输入类型、可变缓冲区独立性、深嵌套、显式栈以及工作量计数。`tests/test_errors_limits.py` 覆盖截断、畸形 TLV、全部资源限制的边界情况和失败后 `reset()`。测试还会比较不同分片下的帧输出、错误类别和全局位置。

模糊测试位于 `tests/fuzz_harness.py` 和 `tests/test_fuzz.py`：

- 固定种子 `0x5EED1234`，固定 500 个结构化有效输入和 2,500 个变异输入；
- 生成器独立编码字节流并直接记录预期的 `ParsedFrame`/节点树，不使用被测解析器生成“期望值”；
- 变异覆盖帧字段损坏、正文长度加减、节点长度超大、容器尾部、容器过短、截断和合法类型变更；
- 每个输入使用整段、逐字节和确定性随机碎片三种方案，比较帧、错误类别、`offset` 和结束状态；
- 预期协议拒绝和 Python 程序异常分开记录；任何未处理异常、意外成功、输出不一致或 watchdog 超时都会使测试失败。

失败记录保存随机种子、完整输入十六进制、限制配置、分片方案、预期结果、实际结果和异常栈（若有），位于 `artifacts/fuzz_failures/*.json`。`tests.fuzz_harness.load_failure()` 和 `replay_record()` 可离线重放。仓库中保留了一次开发期逐字节容器边界缺陷产生的失败记录；修复后这些记录均可重放通过，且该缺陷已由逐字节嵌套回归测试覆盖。

## 安全边界与已知限制

- 本库只负责 TLM1 结构和资源限额，不提供认证、加密、重放防护、语义校验或业务字段验证。
- 调用方仍必须限制单连接/单进程的总输入量、输入速率、保留时间、帧处理并发度和下游对象生命周期。
- 合法帧的结果树会占用与允许协议字节和节点数成比例的内存；逻辑限额不等于硬性进程 RSS 上限。
- 一个 `FrameParser` 只保存至多一个未完成帧。若调用方把超大输入段交给 `feed()`，解析器自身不会复制整段，但该输入段的内存仍由调用方持有。
- 模糊测试是有限规模的确定性抽样；“未发现问题”不等于不存在漏洞。
