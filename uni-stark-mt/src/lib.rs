//! Multi-trace STARK prover for Plonky3
//!
//! This crate extends Plonky3's univariate STARK framework to support two-phase proving:
//! 1. Main trace commitment
//! 2. Challenge sampling
//! 3. Auxiliary trace generation (using challenges)
//! 4. Auxiliary trace commitment
//! 5. Quotient polynomial evaluation
//! 6. Opening proofs
//!
//! The key abstraction is [`AuxTraceBuilder`], which allows AIRs to specify how to build
//! auxiliary trace columns from the main trace and random challenges.

#![no_std]

extern crate alloc;

mod air;
mod config;
mod folder;
mod proof;
mod prover;
mod verifier;

pub use air::*;
pub use config::*;
pub use folder::*;
pub use proof::*;
pub use prover::*;
pub use verifier::*;

// Re-export key Plonky3 types
pub use p3_air::{Air as P3Air, AirBuilder, BaseAir};
pub use p3_field::{ExtensionField, Field};
pub use p3_matrix::dense::RowMajorMatrix;
