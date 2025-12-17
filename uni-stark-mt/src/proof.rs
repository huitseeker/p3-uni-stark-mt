//! Proof structures

use alloc::vec::Vec;

/// A multi-trace STARK proof.
#[derive(Clone)]
pub struct Proof<SC: crate::StarkGenericConfig> {
    /// Commitment to the main trace
    pub main_commit: <SC::Pcs as p3_commit::Pcs<SC::Challenge, SC::Challenger>>::Commitment,

    /// Commitment to the auxiliary trace (None if no aux trace)
    pub aux_commit: Option<<SC::Pcs as p3_commit::Pcs<SC::Challenge, SC::Challenger>>::Commitment>,

    /// Commitment to quotient polynomial chunks (all chunks in one commitment)
    pub quotient_commit: <SC::Pcs as p3_commit::Pcs<SC::Challenge, SC::Challenger>>::Commitment,

    /// Opened values of main trace at ζ (out-of-domain point)
    pub main_local: Vec<SC::Challenge>,

    /// Opened values of main trace at ζ·g (next row)
    pub main_next: Vec<SC::Challenge>,

    /// Opened values of aux trace at ζ (if aux trace exists)
    pub aux_local: Vec<SC::Challenge>,

    /// Opened values of aux trace at ζ·g (if aux trace exists)
    pub aux_next: Vec<SC::Challenge>,

    /// Opened values of quotient chunks at ζ
    /// Each chunk is a Vec<Challenge> (all columns in that chunk at zeta)
    pub quotient_chunks: Vec<Vec<SC::Challenge>>,

    /// PCS opening proof
    pub opening_proof: <SC::Pcs as p3_commit::Pcs<SC::Challenge, SC::Challenger>>::Proof,

    /// Degree (log2 of trace height)
    pub log_degree: u8,
}
