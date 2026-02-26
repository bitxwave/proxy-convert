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
        // Ensure handle_version does not panic
        handle_version();
        assert!(true);
    }

    #[test]
    fn test_version_output_format() {
        // Version string format
        let version = env!("CARGO_PKG_VERSION");
        assert!(!version.is_empty());
        assert!(version.chars().any(|c| c.is_ascii_digit()));
    }
}
