#![no_std]

mod events;
pub use events::EventKind;
pub use events::TtyEvent;
pub use events::JitterCommand;