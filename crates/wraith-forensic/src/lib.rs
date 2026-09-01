rust_i18n::i18n!("locales");

pub mod anti_debug_probe;
pub mod anti_fingerprint;
pub mod anti_forensic_stealth;
pub mod browser;
pub mod display_jail;
pub mod font_jail;
pub mod hardware_cloaker;
pub mod logs;
pub mod memory;
pub mod shred;

pub use anti_debug_probe::*;
pub use anti_fingerprint::*;
pub use anti_forensic_stealth::*;
pub use browser::*;
pub use display_jail::*;
pub use font_jail::*;
pub use hardware_cloaker::*;
pub use logs::*;
pub use memory::*;
pub use shred::*;

