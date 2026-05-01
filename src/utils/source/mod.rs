//! Source IO: remote/file fetching and orchestration. Domain types
//! (Source, Config) live in `crate::protocols::source`.

pub mod loader;

pub use loader::SourceLoader;
