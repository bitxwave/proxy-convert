//! Version command module

/// Display version information
pub fn handle_version() {
    println!("proxy-convert v{}", env!("CARGO_PKG_VERSION"));
    println!("A modern, extensible proxy configuration conversion tool");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_version() {
        // 测试版本命令不会panic
        // 由于handle_version只是打印信息，我们主要测试它不会崩溃
        handle_version();
        assert!(true); // 如果能执行到这里，说明没有panic
    }

    #[test]
    fn test_version_output_format() {
        // 测试版本信息格式
        let version = env!("CARGO_PKG_VERSION");
        assert!(!version.is_empty());
        assert!(version.chars().any(|c| c.is_ascii_digit()));
    }
}
