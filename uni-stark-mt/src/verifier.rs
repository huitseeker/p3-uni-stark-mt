//! Verifier implementation for multi-trace STARK

use alloc::vec;
use alloc::vec::Vec;

use itertools::Itertools;
use p3_air::Air;
use p3_challenger::{CanObserve, CanSample};
use p3_commit::{Pcs, PolynomialSpace};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use tracing::instrument;

use crate::{Challenge, Domain, MultiTraceAir, Proof, Val, VerifierFolder};

/// Verification error types
#[derive(Debug)]
pub enum VerificationError {
    /// PCS verification failed
    PcsVerificationFailed,
    /// Constraint evaluation failed
    ConstraintVerificationFailed,
    /// Invalid proof structure
    InvalidProof(&'static str),
}

/// Recomposes the quotient polynomial from its chunks evaluated at a point.
///
/// Given quotient chunks and their domains, this computes the Lagrange
/// interpolation coefficients (zps) and reconstructs quotient(zeta).
pub fn recompose_quotient_from_chunks<SC>(
    quotient_chunks_domains: &[Domain<SC>],
    quotient_chunks: &[Vec<Challenge<SC>>],
    zeta: Challenge<SC>,
) -> Challenge<SC>
where
    SC: crate::StarkGenericConfig,
{
    let zps = quotient_chunks_domains
        .iter()
        .enumerate()
        .map(|(i, domain)| {
            quotient_chunks_domains
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, other_domain)| {
                    other_domain.vanishing_poly_at_point(zeta)
                        * other_domain
                            .vanishing_poly_at_point(domain.first_point())
                            .inverse()
                })
                .product::<Challenge<SC>>()
        })
        .collect_vec();

    // Each chunk is a Vec<Challenge> representing the columns at that point
    // After flattening to base, each extension field element becomes
    // DIMENSION base field elements (e.g., 4 for degree-4 extension)
    quotient_chunks
        .iter()
        .enumerate()
        .map(|(ch_i, chunk_vals)| {
            // Reconstruct the Challenge from its base field components
            zps[ch_i]
                * chunk_vals
                    .iter()
                    .enumerate()
                    .map(|(e_i, &c)| Challenge::<SC>::ith_basis_element(e_i).unwrap() * c)
                    .sum::<Challenge<SC>>()
        })
        .sum::<Challenge<SC>>()
}

/// Verify a multi-trace STARK proof.
///
/// # Arguments
/// - `config`: STARK configuration (must match prover's config)
/// - `air`: The AIR defining the computation (must match prover's AIR)
/// - `proof`: The proof to verify
/// - `public_values`: Public input/output values (must match prover's)
///
/// # Returns
/// - `Ok(())` if the proof is valid
/// - `Err(VerificationError)` if verification fails
#[instrument(skip_all, fields(log_degree = proof.log_degree))]
pub fn verify<SC, A>(
    config: &SC,
    air: &A,
    proof: &Proof<SC>,
    public_values: &[Val<SC>],
) -> Result<(), VerificationError>
where
    SC: crate::StarkGenericConfig,
    A: MultiTraceAir<Val<SC>, Challenge<SC>> + for<'a> Air<VerifierFolder<'a, SC>>,
{
    // Check basic proof structure
    if air.aux_width() > 0 && proof.aux_commit.is_none() {
        return Err(VerificationError::InvalidProof(
            "AIR requires auxiliary trace but proof has none",
        ));
    }

    if air.aux_width() == 0 && proof.aux_commit.is_some() {
        return Err(VerificationError::InvalidProof(
            "AIR has no auxiliary trace but proof includes one",
        ));
    }

    let pcs = config.pcs();
    let mut challenger = config.initialise_challenger();

    // Reconstruct the verifier's view of the protocol
    let height = 1 << proof.log_degree;
    let trace_domain = pcs.natural_domain_for_degree(height);

    // Observe main trace commitment (same as prover)
    challenger.observe(proof.main_commit.clone());
    challenger.observe_slice(public_values);

    // Observe auxiliary commitment if present
    if let Some(ref aux_commit) = proof.aux_commit {
        // Sample challenges (same as prover)
        let num_challenges = air.num_challenges();
        for _ in 0..num_challenges {
            let _: Challenge<SC> = challenger.sample();
        }

        challenger.observe(aux_commit.clone());
    }

    // Sample alpha for constraint combination (same as prover - must be BEFORE quotient commits)
    let alpha: Challenge<SC> = challenger.sample();

    // Observe quotient commitment
    challenger.observe(proof.quotient_commit.clone());

    // Sample out-of-domain point (same as prover)
    let zeta: Challenge<SC> = challenger.sample();
    let _zeta_next = trace_domain
        .next_point(zeta)
        .expect("domain must support next_point");

    // Compute quotient degree and domains (must match prover)
    let constraint_degree = 2; // Must match prover's heuristic
    let quotient_degree = 1 << constraint_degree;
    let quotient_domain = trace_domain.create_disjoint_domain(height * quotient_degree);
    let quotient_chunk_domains = quotient_domain.split_domains(quotient_degree);

    // Build PCS opening verification data
    // Format: Vec<(Commitment, Vec<(Domain, Vec<(Point, Values)>)>)>
    let mut coms_to_verify = vec![(
        proof.main_commit.clone(),
        vec![(
            trace_domain,
            vec![
                (zeta, proof.main_local.clone()),
                (_zeta_next, proof.main_next.clone()),
            ],
        )],
    )];

    if let Some(ref aux_commit) = proof.aux_commit {
        coms_to_verify.push((
            aux_commit.clone(),
            vec![(
                trace_domain,
                vec![
                    (zeta, proof.aux_local.clone()),
                    (_zeta_next, proof.aux_next.clone()),
                ],
            )],
        ));
    }

    // Add quotient commitment with all chunks
    // Each chunk is opened at zeta on its own domain
    let quotient_openings: Vec<(Domain<SC>, Vec<(Challenge<SC>, Vec<Challenge<SC>>)>)> =
        quotient_chunk_domains
            .iter()
            .enumerate()
            .map(|(i, &domain)| (domain, vec![(zeta, proof.quotient_chunks[i].clone())]))
            .collect();

    coms_to_verify.push((proof.quotient_commit.clone(), quotient_openings));

    // Verify PCS opening proofs
    pcs.verify(coms_to_verify, &proof.opening_proof, &mut challenger)
        .map_err(|_| VerificationError::PcsVerificationFailed)?;

    // Compute selectors at zeta
    let selectors = trace_domain.selectors_at_point(zeta);

    // Evaluate constraints at zeta
    let mut folder = VerifierFolder {
        main_local: &proof.main_local,
        main_next: &proof.main_next,
        aux_local: &proof.aux_local,
        aux_next: &proof.aux_next,
        is_first_row: selectors.is_first_row,
        is_last_row: selectors.is_last_row,
        is_transition: selectors.is_transition,
        alpha,
        accumulator: SC::Challenge::ZERO,
    };

    air.eval(&mut folder);
    let constraints_at_zeta = folder.accumulator;

    // Reconstruct quotient value from chunks using Lagrange interpolation
    let quotient_at_zeta =
        recompose_quotient_from_chunks::<SC>(&quotient_chunk_domains, &proof.quotient_chunks, zeta);

    // Check: C(zeta) / Z_H(zeta) == Q(zeta)
    // Equivalently: C(zeta) * inv_Z_H(zeta) == Q(zeta)
    // The selector provides inv_vanishing = 1/Z_H(zeta)
    if constraints_at_zeta * selectors.inv_vanishing != quotient_at_zeta {
        return Err(VerificationError::ConstraintVerificationFailed);
    }

    Ok(())
}
