# Proxy Config Converter

A modern, extensible proxy configuration conversion tool supporting conversion and multi-source integration between various proxy configuration formats.

## 🚀 Features

- **Multi-protocol support**: Supports Clash, Sing-box, V2Ray and other proxy configuration formats
- **Multi-source integration**: Supports integration of multiple input sources with unified interpolation rules ✨
- **URL-style source**: Source uses standard URL form `<path|url>?type=...&name=...&flag=...` for easy extension ✨
- **Powerful interpolation system**: Advanced template interpolation rules for complex node selection and filtering ✨
- **Plugin architecture**: Easy to extend new protocol support
- **Modern CLI**: User-friendly command line interface based on clap 4.x
- **Async processing**: High-performance async processing based on tokio
- **Structured logging**: Full logging system using tracing
- **Config management**: Flexible config file and environment variable support
- **Error handling**: Robust error handling and user-friendly error messages
- **Type safety**: Strong type system, compile-time checks

## 📦 Installation

### Build from source

```bash
git clone https://github.com/your-username/proxy-convert.git
cd proxy-convert
cargo build --release
```

### Install via Cargo

```bash
cargo install --git https://github.com/your-username/proxy-convert.git
```

## 🎯 Quick Start

### Basic Usage

```bash
# Recommended: URL-style (path/url + query params)
proxy-convert convert --source "./clash.yaml?type=clash"
proxy-convert convert --source "https://example.com/sub?type=clash&name=my&flag=clash" -o config.json

# Legacy: name@type@source or type@source
proxy-convert convert --source "clash1@clash@./clash.yaml" --source "singbox1@sing-box@./singbox.json" -o config.json

# Validate config file
proxy-convert validate config.json

# Generate template
proxy-convert template singbox --output template.json

# Show version info
proxy-convert version
```

## 🔧 Multi-Source Mode

### Important Note

**Single source and multiple sources use exactly the same interpolation rules and input rules!**

This ensures consistent user experience regardless of whether you use a single input source or multiple input sources.

### Source Format (standard URL-style)

```text
<path|url>?type=clash&name=...&flag=...
```

- Path or URL + `?` and query params (standard URL): `type` (required), `name` (optional), `flag` (optional).
- Examples: `./config.yaml?type=clash`, `https://example.com/sub?type=clash&name=my&flag=clash`
- Config file `sources` use the same format (list of such strings).

### Examples

```bash
--source "./clash.yaml?type=clash"
--source "https://example.com/sub?type=clash&name=my&flag=clash"
--source "examples/sources/Eternal Network?type=singbox"
# With config: --config examples/config.yaml -o config.json
```

## 📋 Interpolation Rules System

The project supports powerful template interpolation rules. Each rule ends with `;` (can be omitted if there's only one rule).

### Basic Interpolation Rules

#### 1. Insert all nodes

```json
{
  "outbounds": "{{ALL-TAG}}"
}
```

#### 2. Insert all nodes from specified source

```json
{
  "outbounds": "{{ALL-TAG:clash1}}"
}
```

#### 3. Insert all nodes from multiple sources

```json
{
  "outbounds": "{{ALL-TAG:clash1,singbox1}}"
}
```

### Tag Filtering Rules

#### 4. Insert nodes matching tags from all sources

```json
{
  "outbounds": "{{INCLUDE-TAG:US,JP,SG}}"
}
```

#### 5. Insert nodes matching tags from specified source

```json
{
  "outbounds": "{{INCLUDE-TAG:clash1@US,JP}}"
}
```

#### 6. Insert nodes matching tags from multiple sources

```json
{
  "outbounds": "{{INCLUDE-TAG:clash1@US,JP,singbox1@SG}}"
}
```

### Exclusion Rules

#### 7. Exclude nodes matching tags from all sources

```json
{
  "outbounds": "{{EXCLUDE-TAG:CN,AD}}"
}
```

#### 8. Exclude nodes matching tags from specified source

```json
{
  "outbounds": "{{EXCLUDE-TAG:clash1@CN}}"
}
```

#### 9. Exclude nodes matching tags from multiple sources

```json
{
  "outbounds": "{{EXCLUDE-TAG:clash1@CN,AD,singbox1@BLOCKED}}"
}
```

### Tag Prefix Rules

When using `source-name@tag` format, the final node tags automatically include source prefixes:

- Nodes matching `clash1@US` will have tags containing `clash1@US`
- Nodes matching `singbox1@SG` will have tags containing `singbox1@SG`

### Template Example

```json
{
  "outbounds": [
    {
      "type": "urltest",
      "tag": "Hong Kong Nodes",
      "outbounds": "{{ALL-TAG:clash1}}",
      "url": "https://www.gstatic.com/generate_204",
      "interval": "300s"
    },
    {
      "type": "urltest",
      "tag": "US Nodes",
      "outbounds": "{{INCLUDE-TAG:US,JP}}",
      "url": "https://www.gstatic.com/generate_204",
      "interval": "300s"
    },
    {
      "type": "urltest",
      "tag": "Singapore Nodes",
      "outbounds": "{{INCLUDE-TAG:singbox1@SG}}",
      "url": "https://www.gstatic.com/generate_204",
      "interval": "300s"
    },
    {
      "type": "urltest",
      "tag": "Other Nodes",
      "outbounds": "{{EXCLUDE-TAG:US,JP,SG,CN}}",
      "url": "https://www.gstatic.com/generate_204",
      "interval": "300s"
    }
  ]
}
```

## 📋 Command Reference

### `convert` - Convert config format

```bash
proxy-convert convert [OPTIONS] --source <SOURCE> [--source <SOURCE>...]
```

**Arguments:**

- `--source <SOURCE>`: Input source: `<path|url>?type=...&name=...&flag=...` (type required in query)

**Options:**

- `-t, --template <TEMPLATE>`: Template file path
- `-o, --output <OUTPUT>`: Output file path (default: config.json)
- `-f, --format <FORMAT>`: Output format (json/pretty/yaml, default: pretty)
- `-F, --force`: Force overwrite output file
- `-l, --log-level <LOG_LEVEL>`: Log level (default: info)
- `-v, --verbose`: Show detailed information

### `validate` - Validate config format

```bash
proxy-convert validate <FILE> [OPTIONS]
```

**Arguments:**

- `FILE`: Config file path

**Options:**

- `-f, --format <FORMAT>`: Config format

### `template` - Generate template

```bash
proxy-convert template [OPTIONS]
```

**Options:**

- `-o, --output <OUTPUT>`: Output file path (default: template.json)
- `-t, --template-type <TEMPLATE_TYPE>`: Template type (basic/full/minimal, default: basic)

### `version` - Show version info

```bash
proxy-convert version
```

## ⚙️ Configuration

### Config File

The program will look for config files in the following order:

1. `config.yaml` or `config.yml` in the current directory
2. `proxy-convert/config.yaml` or `config.yml` in the user config directory

### Config Example

```yaml
# config.yaml
user_agent: "ProxyConfigConverter/3.0.0"
timeout_seconds: 30
retry_count: 3
cache_ttl_seconds: 3600
log_level: info
output_format: json
default_input_format: clash
default_output_format: singbox
template_dir: ~/.config/proxy-convert/templates
# sources: same format as --source, e.g. ["path?type=clash&name=my"]
# sources:
#   - "./clash.yaml?type=clash&name=clash1"
#   - "https://example.com/sub?type=singbox&name=sub1"
```

### Environment Variables

All config items can be overridden by environment variables in the format `PROXY_CONVERT_<KEY>`:

```bash
export PROXY_CONVERT_LOG_LEVEL=debug
export PROXY_CONVERT_TIMEOUT_SECONDS=60
export PROXY_CONVERT_DEFAULT_OUTPUT_FORMAT=v2ray
```

## 🏗️ Project Structure

```tree
src/
├── main.rs              # Entry point
├── core/                # Core modules
│   ├── error.rs         # Error handling
│   ├── config.rs        # Config management
│   ├── converter.rs     # Core converter
│   ├── http_client.rs   # HTTP client
│   ├── multi_input.rs   # Multi-input integration ✨
│   └── output.rs        # Output management
├── protocols/           # Protocol modules
│   ├── mod.rs           # Protocol registry
│   ├── common/          # Common utilities
│   ├── clash/           # Clash protocol support
│   ├── singbox/         # Sing-box protocol support
│   └── v2ray/           # V2Ray protocol support
├── commands/            # Command modules
│   ├── cli.rs           # CLI definition
│   ├── convert.rs       # Convert command ✨
│   ├── validate.rs      # Validate command
│   ├── template.rs      # Template command
│   └── version.rs       # Version command
└── utils/               # Utility modules
    ├── file.rs          # File operations
    ├── url.rs           # URL processing
    └── template.rs      # Template processing ✨
```

## 🔧 Development

### Multi-Source Integration Architecture ✨

The project supports multi-source integration with unified interpolation rules:

#### 1. Input Source Management

- **Source format**: `<path|url>?type=...&name=...&flag=...` (same for CLI and config)
- **Type detection**: Automatic detection of clash, sing-box, v2ray formats
- **Source naming**: Each source has a unique name for template reference

#### 2. Interpolation Rule System

- **Unified rules**: Single source and multiple sources use identical rules
- **Advanced filtering**: Support for complex tag-based filtering
- **Source-specific rules**: Support for `source-name@tag` format
- **Automatic prefixing**: Tags automatically include source prefixes

#### 3. Template Engine

- **Rule parsing**: Parse interpolation rule strings
- **Node filtering**: Filter and select nodes based on rules
- **Tag processing**: Automatically add source prefixes
- **Template rendering**: Insert node information into templates

#### 4. Node Selection

- **Tag matching**: Filter nodes by tags
- **Protocol matching**: Filter nodes by protocol type
- **Pattern matching**: Filter nodes by name patterns
- **Quantity limits**: Limit the number of selected nodes

#### 5. Transformation Rules

- **Renaming**: Change node names
- **Tag operations**: Add/remove tags
- **Parameter modification**: Change node parameters

### Add New Protocol Support

1. Create a new protocol module under `src/protocols/`
2. Implement the `ProtocolConverter` trait
3. Register the new protocol in `init_protocol_registry()` in `src/main.rs`

### Example: Add New Protocol

```rust
// src/protocols/new_protocol/mod.rs
use crate::utils::error::Result;
use crate::protocols::{ProtocolConverter, ProxyServer};

pub struct NewProtocolConverter;

impl ProtocolConverter for NewProtocolConverter {
    fn name(&self) -> &str {
        "new_protocol"
    }

    fn supported_input_formats(&self) -> &[&str] {
        &["json", "yaml"]
    }

    fn supported_output_formats(&self) -> &[&str] {
        &["singbox", "clash"]
    }

    fn detect_format(&self, content: &str) -> Result<Option<String>> {
        // Implement format detection logic
        Ok(None)
    }

    fn parse_input(&self, content: &str, format: &str) -> Result<Vec<ProxyServer>> {
        // Implement input parsing logic
        Ok(vec![])
    }

    fn generate_output(&self, servers: &[ProxyServer], format: &str, template: Option<&str>) -> Result<String> {
        // Implement output generation logic
        Ok("".to_string())
    }

    fn validate_output(&self, content: &str, format: &str) -> Result<bool> {
        // Implement output validation logic
        Ok(true)
    }
}
```

### Build and Test

```bash
# Build the project
cargo build

# Run tests
cargo test

# Check code quality
cargo clippy

# Format code
cargo fmt
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgements

- [clap](https://github.com/clap-rs/clap) - Command line argument parser
- [tokio](https://github.com/tokio-rs/tokio) - Async runtime
- [serde](https://github.com/serde-rs/serde) - Serialization framework
- [tracing](https://github.com/tokio-rs/tracing) - Structured logging

---

**Note**: This project is for learning and research purposes only. Please comply with local laws and regulations.