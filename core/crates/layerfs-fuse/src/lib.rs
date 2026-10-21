//! Kernel connection/request ownership over existing Workspace semantics.
#![forbid(unsafe_code)]

pub mod coherence;
mod dispatch;
pub mod operations;
pub mod phase;
pub mod ports;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod attributes;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod mount;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod request;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod session;

pub use dispatch::{
    DispatchError, FailureView, InputFailure, MAX_INPUT_BYTES, MountRequests, MountWork,
    RECEIVE_SLOTS, Received, RequestDisposition, RequestFuture, RequestOwner,
};
