# MoonSyncDelta 0.2 — moon_vcdiff 远端签名编码扩展

本项目基于已有 MoonBit 生态库 [`yangxixi00/moon_vcdiff@0.1.0`](https://github.com/yangxixi00/moon-vcdiff) 扩展编码输入方式：接收方保留旧文件并发送块签名，发送方仅凭签名和新文件生成标准 RFC 3284 VCDIFF 补丁，接收方使用已有库解码。

**这是已有生态能力的扩展，存在差量编码功能重合。** 0.1 的独立选题说明不足以回应重合问题；0.2 新增真实依赖、标准格式互通、端到端校验及测试，不以名称或 API 差异宣称不存在竞品。技术关系见 [docs/TOPIC.md](docs/TOPIC.md)。

## 复用与新增

| 能力 | 负责项目 |
|---|---|
| VCDIFF 默认码表、变长整数编码、结构检查、解码 | 直接调用 `yangxixi00/moon_vcdiff`，不复制其源码 |
| 旧文件固定块签名、签名索引与滚动匹配 | 本项目；发送端不接收旧字节 |
| 从匹配操作生成标准 ADD/COPY SELF 补丁 | 本项目 0.2 新增；上游通用编码 API 需要旧、新两个字节数组 |
| 签名/校验元数据交换、旧版本检查与结果 SHA-256 校验 | 本项目；SHA-256 复用 `gmlewis/sha256` |
| 快照、内容寻址存储、备份目录、恢复管理 | 本项目不提供；`bzhangui/moonrestore` 已有相关能力 |

未改动上游仓库，未声称上游作者认可或已合并本扩展。

## 三个使用场景

1. 应用资源更新：安装端以旧资源文件生成签名，分发端输入签名和新资源生成 VCDIFF，安装端使用旧资源解码并校验，得到新资源文件。
2. 离线数据包刷新：用户设备以旧字典或模型数据包生成签名，发布端输入签名和新版二进制生成补丁，设备获得摘要一致的新数据包；传输渠道由应用选择。
3. 二进制缓存更新：缓存节点以本地旧条目生成签名，源站输入签名和新条目生成补丁，节点校验后输出新缓存内容；不实现缓存服务或一致性协议。

这些是可复现的合成工作流，没有外部采用证明。不适合整体变化的压缩/加密内容，算法不保证所有文件节省流量。

## 安装前提与复现

已验证 `moonc v0.10.14+7d59c7ec9` / `moon 0.1.20260920`。需要 Node.js 和 Python 3 执行文件集成验证。

```powershell
moon update
moon check --deny-warn --target all
moon build --target all
moon test --deny-warn --target all
moon run examples/demo
moon build cmd/files --target js --release --deny-warn
python scripts/verify_vcdiff.py
python scripts/verify_files.py
```

本机工具链不在 PATH 时，将 `D:\moonbit-toolchain\bin` 加入 PATH 并设置 `$env:MOON_HOME = 'D:\moonbit-toolchain'`。
模块名 `niuniu513-ask/moon-sync-delta`，仓库 <https://github.com/niuniu513-ask/moon-sync-delta>。0.2 尚未发布 Mooncakes，不声称 `moon add` 已能安装本版本；直接克隆本仓库运行上述命令。

## MoonBit API

```moonbit
let old = b"AAAABBBBCCCCDDDD"
let updated = b"new!AAAABBBBCCCCDDDD"
// 接收端；只发送 sig_wire，不发送 old。
let sig_wire = @sync.encode_signature(@sync.signature(old, block_size=4))
// 发送端；两个输入中没有 old。
let transfer = @sync.create_vcdiff(@sync.decode_signature(sig_wire), updated)
let wire = @sync.encode_vcdiff_transfer(transfer)
// 接收端；内部使用 moon_vcdiff.decode，校验旧版本及新内容摘要。
let restored = @sync.apply_vcdiff(old, @sync.decode_vcdiff_transfer(wire))
assert_eq(restored, updated)
```

以上调用会抛出 `SyncError`。`transfer.payload()` 返回可直接交给 `moon_vcdiff.decode` 的标准 VCDIFF；`wire` 是含校验元数据的 MSVF 封装，不能直接交给标准解码器。可运行例子同时测试原版解码器并报告双文件编码基线的补丁大小，不宣称优于上游压缩率。

## 文件入口

```powershell
moon run cmd/files --target js -- signature old.bin old.sig 2048
# 此步骤仅需 old.sig 和 new.bin，发送端不需要 old.bin。
moon run cmd/files --target js -- vcdiff old.sig new.bin update.msvf
moon run cmd/files --target js -- vcdiff-export update.msvf update.vcdiff
moon run cmd/files --target js -- vcdiff-apply old.bin update.msvf restored.bin
```

所有输出必须不存在。校验完成后才创建重建文件；文件系统写入仍可能失败。`vcdiff-export` 只导出标准补丁，脱离 MSVF 后不再携带本项目的 SHA-256 元数据。认证和授权由应用实现。

CLI 报告 `signature_bytes`、`payload_bytes`、含签名及封装的 `total_wire`；总开销大于等于新文件时输出 `recommend=full`，由调用方实际选择传输方式。小文件通常应全量传输。

## 边界、兼容与许可证

主要交付是单文件、单窗口、默认码表、无二次压缩的 VCDIFF ADD/COPY SELF 编码扩展。通用解码器使用上游实现，本项目封装仅接受文档规定的配置。默认单项数据或帧 64 MiB、100,000 块/操作，字节数可配置至 512 MiB；整块内存处理，峰值内存高于文件大小。不实现网络、目录备份、快照、CAS、元数据同步、认证、rsync 命令或 librsync 格式。

0.1 的 `create_delta/apply_delta`、MSDL 格式及旧 CLI 保留用于兼容与回归，不作为新的独立差量编码器参赛卖点。旧格式见 [docs/WIRE_FORMAT.md](docs/WIRE_FORMAT.md)，新扩展格式见 [docs/VCDIFF_EXTENSION.md](docs/VCDIFF_EXTENSION.md)。

自有代码 MIT；`moon_vcdiff`、`sha256` 及传递依赖遵守各自 Apache-2.0/NOTICE 等要求，见 [SOURCES.md](SOURCES.md)。CI 配置覆盖 Linux/Windows 检查、构建、四后端测试及两套独立文件验证；线上结果须以相应提交的 Actions 为准。本地通过不代表官方初审或最终验收通过。
