//! Route snapshot/apply/restore. The helper is the only process that mutates routes.

mod apply;
mod cidrs;
mod error;

pub use apply::{
    apply_journal, build_plan, detect_default_route, ip_bin, parse_default_route_text,
    restore_added, run_ip, AddedRoute, DefaultRoute, RouteJournal, RoutePlan,
};
pub use cidrs::{is_private, private_cidrs, split_default_v4, split_default_v6};
pub use error::RoutingError;

pub type Result<T> = std::result::Result<T, RoutingError>;
