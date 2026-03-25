pub(crate) mod blocklist;
pub(crate) mod blocklist_analysis;
pub mod config;
pub mod lookup;
pub mod network;
pub mod sync;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}
