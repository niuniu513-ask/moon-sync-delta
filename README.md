# MoonSyncDelta

面向备份、资源分发和数据副本更新的 MoonBit 增量同步基础库。

接收方对旧数据生成块签名，发送方仅根据签名和新数据生成差量，接收方利用旧数据重建结果。
发送方的 `create_delta` API 不接收旧文件，适合发送方无法读取接收方旧副本的场景。

## 三个完整使用场景

1. **客户端备份到远端存储。** 服务端保留上次备份并返回块签名；客户端对新备份生成差量；
   服务端重建并验证完整结果。未变化的块不需要再次上传。
2. **应用资源增量分发。** 安装端对已有资源生成签名；分发端对新资源生成差量；安装端在
   输出新资源前验证旧版本和新结果。支持前部插入、局部替换、删除和块重排。
3. **边缘节点同步数据快照。** 接收节点保留旧快照；发布端读取其签名，发送增量；接收节点
   重建并校验快照。传输渠道由调用方选择，可集成 HTTP、消息队列或文件交换。

这些是适用流程，尚无外部用户采用证明。压缩包、加密数据或整体变化的数据不保证节省流量。

## 与已有生态组件的关系

- `cn-ybm/MoonHashKit` 已提供内容定义分块、去重、清单和缺失块计划，本项目不重新实现 CDC。
- `yangxixi00/moon_vcdiff` 实现 RFC 3284 差量格式，其公开编码 API 接收两个 `Bytes`。
- 本项目关注“发送方仅持有接收方签名”的匹配过程，使用滚动弱校验筛选及 SHA-256 强校验，
  再生成 Copy/Literal 操作并进行完整结果校验。它与上述组件相邻，并非毫无功能交集。

截至 2026-10-11 的检索尚未发现同一完整流程的 MoonBit 项目。检索范围和限制见
[SOURCES.md](SOURCES.md)。这是成熟 rsync 算法的 MoonBit 工程实现，不是全球首创算法。

## 当前已实现

- 固定块签名、最后不足一块的数据签名，以及按长度和弱校验索引的强摘要匹配。
- 每个字节位置的滑动匹配；弱校验一步更新为 O(1)。完整算法还包含强摘要计算，不能一概声称 O(n)。
- 确定性重复块选择、相邻 Copy 合并、二进制字节支持。
- 签名和差量的版本化二进制编码，严格长度、范围及资源限制检查。
- 应用前验证旧数据 SHA-256，返回前验证结果 SHA-256。
- 三个可运行场景和 Node.js 文件操作入口；库核心支持四个 MoonBit 后端。

本版为有界、整块内存 API，默认单个输入、输出或帧不超过 64 MiB。
默认最多 100,000 个签名块或操作；`Limits` 可配置，字节数硬上限 512 MiB。
文件入口固定使用默认限制。内存峰值高于文件长度，本版不承诺大文件流式处理。

## 工具链与运行

已验证编译器 `moonc v0.10.14`、`moon 0.1.20260920`。文件入口还需要 Node.js；独立文件验证需要 Python 3。

```powershell
moon update
moon check --deny-warn --target all
moon build --target all
moon test --deny-warn --target all
moon run examples/demo
```

本机工具链不在 PATH 时：

```powershell
$env:MOON_HOME = 'D:\moonbit-toolchain'
& 'D:\moonbit-toolchain\bin\moon.exe' run examples/demo
```

## 在 MoonBit 项目中使用

```moonbit
let old = b"AAAABBBBCCCCDDDD"
let updated = b"new!AAAABBBBCCCCDDDD"
let signature_wire = @sync.encode_signature(@sync.signature(old, block_size=4))
let delta = @sync.create_delta(@sync.decode_signature(signature_wire), updated)
let delta_wire = @sync.encode_delta(delta)
let restored = @sync.apply_delta(old, @sync.decode_delta(delta_wire))
assert_eq(restored, updated)
```

以上调用会抛出 `SyncError`，需要在可抛错函数或 `try/catch` 中使用。
模块名为 `niuniu513-ask/moon-sync-delta`，源码仓库：
<https://github.com/niuniu513-ask/moon-sync-delta>。尚未发布到 Mooncakes，不能声称 `moon add` 已可安装。
仓库内例子通过 `moon.pkg` 导入该模块。

## 实际文件同步

```powershell
moon run cmd/files --target js -- signature old.bin old.sig 2048
moon run cmd/files --target js -- delta old.sig new.bin update.delta
moon run cmd/files --target js -- apply old.bin update.delta restored.bin
moon run cmd/files --target js -- inspect update.delta
moon run cmd/files --target js -- inspect old.sig
```

`delta` 命令不读取 `old.bin`。所有输出文件必须不存在，避免覆盖源文件。
算法先校验重建结果再创建输出；文件系统写入仍可能因磁盘故障失败。
`inspect` 自动识别签名或差量，显示长度、块数或操作统计及版本摘要；仅验证帧结构，完整性验证需要正确的旧数据。

独立 Python 检查会创建临时二进制文件，通过 Node 入口验证与 Python `hashlib` 一致的摘要、
签名字段、六类更新及失败场景：

```powershell
moon build cmd/files --target js --release
python scripts/verify_files.py
```

## 何时采用全量传输

同时比较签名帧大小和差量帧大小与新文件大小。一次同步中，如果前两者之和更大，优先全量传输。
签名已缓存时可以只比较差量帧；小文件、完全变化的内容通常适合全量传输。
本库提供统计值，传输方式由应用选择。合成实验见 [docs/VALIDATION.md](docs/VALIDATION.md)。
`delta.worth_sending(signature_bytes=signature_wire.length())` 可直接比较两帧总开销；
文件入口也会输出 `recommend=delta` 或 `recommend=full`，但不会擅自更改输出文件类型。

## 边界与许可

本版没有实现 rsync 命令兼容、librsync 文件格式、网络连接、目录遍历、断点续传或文件元数据同步。
项目帧格式见 [docs/WIRE_FORMAT.md](docs/WIRE_FORMAT.md)。SHA-256 校验不替代传输认证。

项目自有代码采用 MIT；SHA-256 复用 Apache-2.0 的 `gmlewis/sha256@0.18.0`，来源及传递依赖见 SOURCES。
CI 已配置，运行结果以 GitHub Actions 为准；Mooncakes 发布尚未完成。
