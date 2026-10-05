rust_i18n::i18n!("locales");

pub mod anti_fingerprint;
pub mod browser;
pub mod display_jail;
pub mod font_jail;
pub mod hardware_cloaker;
pub mod shred;

pub use anti_fingerprint::*;
pub use browser::*;
pub use display_jail::*;
pub use font_jail::*;
pub use hardware_cloaker::*;
pub use shred::*;
