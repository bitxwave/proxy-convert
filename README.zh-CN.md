# Proxy Config Converter

一个现代化、可扩展的代理配置转换工具，支持多种代理配置格式之间的转换和多输入整合。

## 📑 目录

- [🚀 特性](#-特性)
- [📦 安装](#-安装)
- [🎯 快速开始](#-快速开始)
- [📋 插值规则系统](#-插值规则系统-)
- [⚙️ 配置](#️-配置)
- [🏗️ 项目结构](#️-项目结构)
- [🔧 开发](#-开发)
- [❓ 常见问题解答](#-常见问题解答)
- [🤝 贡献指南](#-贡献指南)
- [📄 许可证](#-许可证)
- [🙏 致谢](#-致谢)

## 🚀 特性

- **多协议支持**：支持 Clash、Sing-box、V2Ray 等多种代理配置格式
- **多来源整合**：支持多个输入源的整合和模板规则应用 ✨
- **插值规则系统**：强大的模板插值规则，支持复杂的节点选择和过滤 ✨
- **插件化架构**：易于扩展新的协议支持
- **现代化 CLI**：基于 clap 4.x 的友好命令行界面
- **异步处理**：基于 tokio 的高性能异步处理
- **结构化日志**：使用 tracing 的完整日志系统
- **配置管理**：灵活的配置文件和环境变量支持
- **错误处理**：完善的错误处理和用户友好的错误信息
- **类型安全**：强类型系统，编译时检查

## 📦 安装

### 源码编译

```bash
git clone https://github.com/your-username/proxy-convert.git
cd proxy-convert
cargo build --release
```

### 使用 Cargo 安装

```bash
cargo install --git https://github.com/your-username/proxy-convert.git
```

## 🎯 快速开始

### 基本用法

#### 命令及说明

- 转换订阅

  ```bash
  proxy-convert convert [OPTIONS] --source <SOURCE> [--source <SOURCE>...]
  ```

  **选项：**
  - `--source <SOURCE>`：输入来源，见下方「来源格式说明」
  - `-t, --template <TEMPLATE>`：模板文件路径
  - `-o, --output <OUTPUT>`：输出文件路径（默认：config.json）
  - `-f, --format <FORMAT>`：输出格式（json/pretty/yaml，默认：pretty）
  - `-F, --force`：强制覆盖输出文件
  - `-l, --log-level <LOG_LEVEL>`：日志级别（默认：info）
  - `-v, --verbose`：显示详细信息

  - **来源格式说明**（标准 URL 规范，命令行与配置文件一致）

    ```text
    <path|url>?type=clash&name=...&flag=...
    ```

    - path 或 url 后加 `?` 与查询参数（与标准 URL 一致）：
      - `type`：**必填**，订阅类型（clash / sing-box / v2ray）
      - `name`：可选，来源名称，用于模板引用
      - `flag`：可选，请求 URL 时的 flag 参数（空表示 `&flag=`）
    - 示例：`./config.yaml?type=clash`、`https://example.com/sub?type=clash&name=my&flag=clash`、`examples/sources/Eternal Network?type=singbox`
    - 配置文件 `sources` 也使用相同格式的字符串列表（见下方配置示例）。

- **验证配置文件**：验证配置文件的格式

  ```bash
  proxy-convert validate <FILE> [-f, --format <FORMAT>]
  ```

- **生成模板**：

  ```bash
  proxy-convert template [-o, --output <OUTPUT>] [-t, --template-type <TYPE>]
  ```

- **显示版本信息**：

  ```bash
  proxy-convert version
  ```

#### 使用示例

```bash
# 单源
proxy-convert convert --source "./clash.yaml?type=clash"

# 多源（可带 name、flag）
proxy-convert convert \
  --source "https://example.com/sub?type=clash&name=my&flag=clash" \
  --source "examples/sources/Eternal Network?type=singbox" \
  -o config.json

# 使用配置文件（sources 格式与 --source 一致）
proxy-convert convert --config examples/config.yaml -o config.json

# 其他命令
proxy-convert validate config.json
proxy-convert template singbox --output template.json
proxy-convert version
```

## 📋 插值规则系统 ✨

### 规则说明

本项目支持强大的模板插值规则，每个规则以 `;` 结束（如果只有一个规则可以省略）。

**插值规则特点：**

- **统一性**：单一源和多源使用完全相同的插值规则
- **灵活性**：支持复杂的标签过滤和来源指定
- **可组合性**：多个规则可以组合使用，实现复杂的节点选择逻辑
- **JSON 兼容**：所有插值规则都包含在双引号中，确保 JSON 格式正确

### 基本插值规则

#### 插入所有节点

```json
{
  "outbounds": "{{ALL-TAG}}"
}
```

#### 插入指定来源的所有节点

```json
{
  "outbounds": "{{ALL-TAG:clash1}}"
}
```

#### 插入多个来源的所有节点

```json
{
  "outbounds": "{{ALL-TAG:clash1,singbox1}}"
}
```

### 标签过滤插值规则

#### 插入所有源中匹配标签的节点

```json
{
  "outbounds": "{{INCLUDE-TAG:US,JP,SG}}"
}
```

#### 插入多个来源中匹配标签的节点

```json
{
  "outbounds": "{{INCLUDE-TAG:clash1@US,JP,singbox1@SG}}"
}
```

**说明：** `{{INCLUDE-TAG:clash1@US,JP,singbox1@SG}}` 表示：

- 插入 clash1 来源中匹配 US 的节点
- 插入所有来源中匹配 JP 的节点  
- 插入 singbox1 来源中匹配 SG 的节点

### 排除规则

#### 排除所有源中匹配标签的节点

```json
{
  "outbounds": "{{EXCLUDE-TAG:CN,AD}}"
}
```

#### 排除多个来源中匹配标签的节点

```json
{
  "outbounds": "{{EXCLUDE-TAG:clash1@CN,AD,singbox1@BLOCKED}}"
}
```

**说明：** `{{EXCLUDE-TAG:clash1@CN,AD,singbox1@BLOCKED}}` 表示：

- 排除 clash1 来源中匹配 CN 的节点
- 排除所有来源中匹配 AD 的节点
- 排除 singbox1 来源中匹配 BLOCKED 的节点

#### `INCLUDE-TAG` 和 `EXCLUDE-TAG` 组合使用

`{{INCLUDE-TAG}}` 和 `{{EXCLUDE-TAG}}` 同时存在于同一插值括号中时，它们的组合关系：

- **INCLUDE-TAG**：首先选择匹配指定标签的节点
- **EXCLUDE-TAG**：然后从已选择的节点中排除匹配指定标签的节点
- **最终结果**：INCLUDE 的结果减去 EXCLUDE 的结果

**示例：**

```json
{
  "outbounds": [
    "{{INCLUDE-TAG:US,JP;EXCLUDE-TAG:CN,AD}}",
  ]
}
```

**结果：** 最终只包含 US 和 JP 节点，但不包含 CN 和 AD 节点

### 标签前缀规则

**重要：** 标签前缀规则只适用于多个来源的情况

当使用 `source-name@tag` 格式时，最终节点的标签会自动添加来源前缀：

- 匹配 `clash1@US` 的节点，最终标签会包含 `clash1@US`
- 匹配 `singbox1@SG` 的节点，最终标签会包含 `singbox1@SG`

**单个来源的情况：**

- 如果只有一个来源且没有指定 `name`，节点标签保持原样
- 例如：单源且未指定 `name`（如 `--source "./clash.yaml?type=clash"`）时，节点标签不会添加前缀

**标签前缀的作用：**

- **来源区分**：在多源环境中，可以清楚地区分节点来自哪个来源
- **标签管理**：避免不同来源的相同标签产生冲突
- **模板引用**：在模板中可以使用 `source-name@tag` 格式精确引用特定来源的节点

### 模板示例

```json
{
  "outbounds": [
    {
      "type": "urltest",
      "tag": "香港节点",
      "outbounds": "{{ALL-TAG:clash1}}",
      "url": "https://www.gstatic.com/generate_204",
      "interval": "300s"
    },
    {
      "type": "urltest",
      "tag": "美国节点",
      "outbounds": "{{INCLUDE-TAG:US,JP}}",
      "url": "https://www.gstatic.com/generate_204",
      "interval": "300s"
    },
    {
      "type": "urltest",
      "tag": "新加坡节点",
      "outbounds": "{{INCLUDE-TAG:singbox1@SG}}",
      "url": "https://www.gstatic.com/generate_204",
      "interval": "300s"
    },
    {
      "type": "urltest",
      "tag": "其他节点",
      "outbounds": "{{EXCLUDE-TAG:US,JP,SG,CN}}",
      "url": "https://www.gstatic.com/generate_204",
      "interval": "300s"
    }
  ]
}
```

## ⚙️ 配置

### 配置文件

程序会按以下顺序查找配置文件：

1. 当前目录下的 `config.yaml` 或 `config.yml`
2. 用户配置目录下的 `proxy-convert/config.yaml` 或 `config.yml`

**配置文件优先级：**

- 命令行参数 > 配置文件 > 环境变量 > 默认值

### 配置示例

```yaml
# config.yaml
user_agent: "ProxyConfigConverter/3.0.0"
timeout_seconds: 30
retry_count: 3
log_level: info
output_format: json
default_output_format: singbox
# sources 与 --source 格式一致：<path|url>?type=...&name=...&flag=...
# sources:
#   - "./clash.yaml?type=clash&name=clash1"
#   - "https://example.com/sub?type=singbox&name=sub1"
```

**配置项说明：**

- `user_agent`：HTTP 请求的 User-Agent
- `timeout_seconds`：网络请求超时时间（秒）
- `retry_count`：失败重试次数
- `log_level`：日志级别（error/warn/info/debug/trace）
- `default_output_format`：默认输出协议（singbox/clash/v2ray）
- `output_format`：输出格式（json/pretty/yaml）
- `output`：默认输出文件路径
- `template`：默认模板文件路径
- `sources`：预定义来源列表（与命令行 `--source` 格式一致）

### 环境变量

所有配置项均可通过环境变量覆盖，格式为 `PROXY_CONVERT_<KEY>`（嵌套键使用 `__`）：

```bash
export PROXY_CONVERT_LOG_LEVEL=debug
export PROXY_CONVERT_TIMEOUT_SECONDS=60
export PROXY_CONVERT_DEFAULT_OUTPUT_FORMAT=v2ray
```

**配置优先级：** 命令行 > 环境变量 > 配置文件 > 默认值

## 🏗️ 项目结构

```tree
src/
├── main.rs              # 程序入口，CLI 命令分发
├── lib.rs               # 库入口，供二进制与集成测试使用
├── core/                 # 领域与核心
│   ├── config.rs        # 配置管理
│   ├── error.rs         # 全局错误类型
│   ├── logging.rs      # 日志初始化
│   └── source.rs        # SourceMeta、SourceProtocol（领域类型）
├── protocols/           # 协议模块
│   ├── mod.rs           # 协议注册表、ProxyServer、ProtocolProcessor
│   ├── detect.rs        # 格式检测（clash/singbox/v2ray/subscription/plain）
│   ├── subscription.rs  # 订阅与纯文本解析（vmess/trojan/ss URL）
│   ├── clash/           # Clash 协议支持
│   ├── singbox/         # Sing-box 协议支持
│   └── v2ray/           # V2Ray 协议支持
├── commands/            # CLI 命令
│   ├── cli.rs           # CLI 定义
│   ├── convert.rs      # 转换命令
│   ├── validate.rs     # 验证命令
│   ├── template.rs     # 模板命令
│   └── version.rs      # 版本命令
└── utils/               # 工具
    ├── source/         # 来源加载与解析
    └── template/       # 模板插值与引擎
```

**模块职责说明：**

- **core**：领域类型与全局错误、配置、日志
- **protocols**：格式检测、订阅解析、各协议实现与 Processor 注册
- **commands**：CLI 命令实现
- **utils**：来源加载、模板解析与渲染

## 🔧 开发

### 核心架构 ✨

本项目支持多来源整合，主要组件包括：

#### 1. 输入源管理

- **来源格式**：统一使用 URL 形式 `<path|url>?type=...&name=...&flag=...`（命令行与配置文件一致）
- **类型检测**：自动检测 clash、sing-box、v2ray 格式
- **来源命名**：每个来源都有唯一名称用于模板引用

#### 2. 插值规则系统

- **统一规则**：单一源和多源使用完全相同的规则
- **高级过滤**：支持复杂的基于标签的过滤
- **来源特定规则**：支持 `source-name@tag` 格式
- **自动前缀**：标签自动包含来源前缀

#### 3. 模板引擎

- **规则解析**：解析插值规则字符串
- **节点过滤**：根据规则过滤和选择节点
- **标签处理**：自动添加来源前缀
- **模板渲染**：将节点信息插入到模板中

#### 4. 节点选择

- **标签匹配**：按标签过滤节点
- **协议匹配**：按协议类型过滤节点
- **模式匹配**：按名称模式过滤节点
- **数量限制**：限制选择的节点数量

#### 5. 转换规则

- **重命名**：修改节点名称
- **标签操作**：添加/移除标签
- **参数修改**：修改节点参数

### 添加新的协议支持

1. 在 `src/protocols/` 下创建新的协议模块
2. 实现 `ProtocolProcessor` trait（模板处理）
3. 在 `src/protocols/mod.rs` 的 `ProtocolRegistry::init()` 中注册：
   `registry.register("format_name", Box::new(YourProcessor));`
4. 若需支持该格式的解析，在 Registry 中补充对应 `parse_content` 等逻辑（如 subscription/plain 使用 `subscription` 模块）

### 示例：添加新协议

```rust
// src/protocols/new_protocol/mod.rs
use crate::core::error::Result;
use crate::protocols::{ProtocolProcessor, ProxyServer};
use crate::utils::template::interpolation_parser::InterpolationRule;
use indexmap::IndexMap;
use crate::utils::source::parser::Source;

pub struct NewProtocolProcessor;

impl ProtocolProcessor for NewProtocolProcessor {
    fn process_rule(&self, _rule: &InterpolationRule, _sources: &IndexMap<String, Source>) -> Result<String> {
        Ok(String::new())
    }
    fn get_nodes_for_rule(&self, rule: &InterpolationRule, sources: &IndexMap<String, Source>) -> Result<Vec<ProxyServer>> {
        // ...
    }
    fn set_default_values(&self, template: &str, nodes: &[ProxyServer]) -> Result<String> {
        // ...
    }
    fn append_nodes(&self, template: &str, nodes: &[ProxyServer]) -> Result<String> {
        // ...
    }
    fn create_node_config(&self, node: &ProxyServer) -> String {
        // ...
    }
}
```

然后在 `ProtocolRegistry::init()` 中注册：

```rust
registry.register("new_protocol", Box::new(new_protocol::NewProtocolProcessor));
```

### 构建与测试

```bash
# 构建项目
cargo build
cargo build --release

# 运行测试（含单元测试与 tests/ 下集成测试）
cargo test

# 代码质量
cargo clippy
cargo fmt
```

### 开发环境设置

```bash
# 安装 Rust 工具链
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 安装开发工具
rustup component add rustfmt
rustup component add clippy

# 安装有用的开发工具
cargo install cargo-watch      # 文件变化时自动重新构建
cargo install cargo-expand     # 宏展开工具
cargo install cargo-tree       # 依赖树可视化
```

### 调试和日志

```bash
# 设置日志级别
export RUST_LOG=debug

# 运行程序并显示详细日志
cargo run -- --log-level debug

# 使用 cargo-watch 进行开发
cargo watch -x check -x test -x run
```

## 📄 许可证

本项目采用 MIT 许可证，详见 [LICENSE](LICENSE) 文件。

## 🤝 贡献指南

我们欢迎所有形式的贡献！如果您想为项目做出贡献，请：

### 贡献方式

1. **报告问题**：在 GitHub Issues 中报告 bug 或提出功能建议
2. **提交代码**：Fork 项目并提交 Pull Request
3. **改进文档**：帮助完善文档和示例
4. **分享经验**：在 Discussions 中分享使用经验和最佳实践

### 开发流程

1. Fork 项目到您的 GitHub 账户
2. 创建功能分支：`git checkout -b feature/your-feature`
3. 提交更改：`git commit -am 'Add some feature'`
4. 推送分支：`git push origin feature/your-feature`
5. 创建 Pull Request

### 代码规范

- 遵循 Rust 官方编码规范
- 使用 `cargo fmt` 格式化代码
- 通过 `cargo clippy` 检查代码质量
- 为新功能添加测试用例
- 更新相关文档

## 🙏 致谢

- [clap](https://github.com/clap-rs/clap) - 命令行参数解析库
- [tokio](https://github.com/tokio-rs/tokio) - 异步运行时
- [serde](https://github.com/serde-rs/serde) - 序列化框架
- [tracing](https://github.com/tokio-rs/tracing) - 结构化日志

## ❓ 常见问题解答

### Q: 如何处理多个来源中相同标签的节点？

A: 当多个来源包含相同标签的节点时，程序会自动为节点名称添加来源前缀。例如：

- `clash1` 来源的 `US` 节点会变成 `clash1@US`
- `singbox1` 来源的 `US` 节点会变成 `singbox1@US`

### Q: 插值规则中的标签匹配是精确匹配还是模糊匹配？

A: 目前支持精确匹配。标签必须完全匹配才能被选中或排除。

### Q: 如何添加自定义的插值规则？

A: 可以在 `src/utils/template.rs` 中的 `InterpolationRule` 枚举中添加新的规则类型，并在 `TemplateEngine` 中实现相应的处理逻辑。

### Q: 配置文件中的 source 配置和命令行参数有什么区别？

A: 配置文件中的 source 配置是预定义的来源列表，可以通过命令行参数覆盖。命令行参数的优先级更高。

### Q: 如何处理网络请求失败的情况？

A: 程序支持重试机制，可以通过配置文件设置 `retry_count` 和 `timeout_seconds` 来控制重试行为。

### Q: 如何扩展支持新的代理协议？

A: 参考文档中的「添加新的协议支持」部分，实现 `ProtocolProcessor` trait 并在 `ProtocolRegistry::init()` 中注册。

### Q: 模板文件中的插值规则必须用引号包围吗？

A: 是的，为了确保 JSON 格式的正确性，所有插值规则都必须用双引号包围。

---

**注意**：本项目仅用于学习和研究目的，请遵守当地法律法规。