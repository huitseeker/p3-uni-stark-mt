//! Prover implementation for multi-trace STARK

use alloc::vec;
use alloc::vec::Vec;

use p3_air::Air;
use p3_challenger::{CanObserve, CanSample};
use p3_commit::{Pcs, PolynomialSpace};
use p3_field::{PackedField, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_util::log2_strict_usize;
use tracing::{info_span, instrument};

use crate::{Challenge, MultiTraceAir, Proof, ProverFolder, Val};

/// Prove a computation using a multi-trace AIR.
///
/// # Arguments
/// - `config`: STARK configuration (PCS, challenger)
/// - `air`: The AIR defining the computation
/// - `main_trace`: The main execution trace
/// - `public_values`: Public input/output values
///
/// # Returns
/// A proof that can be verified with [`crate::verify`]
///
/// # Panics
/// - If trace dimensions don't match AIR width
/// - If auxiliary trace building fails
#[instrument(skip_all, fields(trace_height = main_trace.height()))]
pub fn prove<SC, A>(
    config: &SC,
    air: &A,
    main_trace: RowMajorMatrix<Val<SC>>,
    public_values: &[Val<SC>],
) -> Proof<SC>
where
    SC: crate::StarkGenericConfig,
    Val<SC>: PackedField,
    A: MultiTraceAir<Val<SC>, Challenge<SC>>
        + for<'a> Air<ProverFolder<'a, SC>>
        + for<'a> Air<crate::VerifierFolder<'a, SC>>,
{
    assert_eq!(main_trace.width(), air.width(), "Main trace width mismatch");

    let pcs = config.pcs();
    let mut challenger = config.initialise_challenger();

    // Trace dimensions
    let height = main_trace.height();
    let log_degree = log2_strict_usize(height) as u8;
    let trace_domain = pcs.natural_domain_for_degree(height);

    // ==================== PHASE 1: Main Trace ====================
    info_span!("commit main trace").in_scope(|| {
        tracing::info!("Committing main trace (height={})", height);
    });

    let (main_commit, main_data) =
        info_span!("pcs_commit_main").in_scope(|| pcs.commit([(trace_domain, main_trace.clone())]));

    // Observe main trace commitment
    challenger.observe(main_commit.clone());
    challenger.observe_slice(public_values);

    // ==================== PHASE 2: Auxiliary Trace ====================
    let (aux_commit, aux_data, _aux_trace) = if air.aux_width() > 0 {
        info_span!("auxiliary phase").in_scope(|| {
            // Sample challenges
            let num_challenges = air.num_challenges();
            let challenges: Vec<Challenge<SC>> =
                (0..num_challenges).map(|_| challenger.sample()).collect();

            tracing::info!("Sampled {} challenges for auxiliary trace", num_challenges);

            // Build auxiliary trace using challenges
            // Pass the original main_trace (not LDE) to build_aux_trace
            let aux_trace = air.build_aux_trace(&main_trace, &challenges);

            assert_eq!(
                aux_trace.width,
                air.aux_width(),
                "Auxiliary trace width mismatch"
            );
            assert_eq!(
                aux_trace.height(),
                height,
                "Auxiliary trace height mismatch"
            );

            tracing::info!(
                "Built auxiliary trace ({}x{})",
                aux_trace.height(),
                aux_trace.width
            );

            // Commit auxiliary trace (flatten to base field first)
            let aux_trace_flat = aux_trace.clone().flatten_to_base();
            let (aux_commit, aux_data) = info_span!("pcs_commit_aux")
                .in_scope(|| pcs.commit([(trace_domain, aux_trace_flat)]));

            // Observe auxiliary commitment
            challenger.observe(aux_commit.clone());

            (Some(aux_commit), Some(aux_data), Some(aux_trace))
        })
    } else {
        (None, None, None)
    };

    // ==================== PHASE 3: Quotient Polynomial ====================
    info_span!("quotient computation").in_scope(|| {
        tracing::info!("Computing quotient polynomial");
    });

    // Sample challenge for combining constraints
    let alpha: Challenge<SC> = challenger.sample();

    // Compute constraint polynomial degree
    // TODO: For now using a simple heuristic; should compute symbolically
    let constraint_degree = 2; // Most common case
    let quotient_degree = 1 << constraint_degree;

    // Create larger domain for quotient evaluation
    let quotient_domain = trace_domain.create_disjoint_domain(height * quotient_degree);

    // Get trace evaluations on quotient domain
    let main_on_quotient = pcs.get_evaluations_on_domain(&main_data, 0, quotient_domain);
    let aux_on_quotient = aux_data
        .as_ref()
        .map(|data| pcs.get_evaluations_on_domain(data, 0, quotient_domain));

    // Compute quotient values
    let quotient_values = compute_quotient_values(
        air,
        trace_domain,
        quotient_domain,
        &main_on_quotient,
        aux_on_quotient.as_ref(),
        alpha,
        public_values,
    );

    // Commit to quotient polynomial chunks
    let quotient_flat = RowMajorMatrix::new_col(quotient_values).flatten_to_base();
    let quotient_chunks = quotient_domain.split_evals(quotient_degree, quotient_flat);
    let quotient_chunk_domains = quotient_domain.split_domains(quotient_degree);

    // Commit all chunks together (not separately)
    let (quotient_commit, quotient_data) = info_span!("pcs_commit_quotient").in_scope(|| {
        pcs.commit(
            quotient_chunk_domains
                .iter()
                .copied()
                .zip(quotient_chunks.into_iter())
                .collect::<Vec<_>>(),
        )
    });

    // Observe quotient commitment
    challenger.observe(quotient_commit.clone());

    // ==================== PHASE 4: Opening ====================
    info_span!("opening").in_scope(|| {
        tracing::info!("Computing opening proofs");
    });

    // Sample out-of-domain evaluation point
    let zeta: Challenge<SC> = challenger.sample();
    let zeta_next = trace_domain
        .next_point(zeta)
        .expect("domain must support next_point");

    // Open all committed polynomials
    let mut opening_points = vec![(&main_data, vec![vec![zeta, zeta_next]])];

    if let Some(ref aux_data) = aux_data {
        opening_points.push((aux_data, vec![vec![zeta, zeta_next]]));
    }

    // Open all quotient chunks at zeta (they're all in one commitment now)
    let quotient_opening_points: Vec<Vec<Challenge<SC>>> =
        quotient_chunk_domains.iter().map(|_| vec![zeta]).collect();
    opening_points.push((&quotient_data, quotient_opening_points));

    let (opened_values, opening_proof) = pcs.open(opening_points, &mut challenger);

    // Extract opened values
    let mut values_iter = opened_values.into_iter();

    // Main trace openings
    let main_openings = values_iter.next().unwrap();
    let main_local = main_openings[0][0].clone();
    let main_next = main_openings[0][1].clone();

    // Auxiliary trace openings (if present)
    let (aux_local, aux_next) = if aux_data.is_some() {
        let aux_openings = values_iter.next().unwrap();
        (aux_openings[0][0].clone(), aux_openings[0][1].clone())
    } else {
        (vec![], vec![])
    };

    // Quotient chunk openings
    // All quotient chunks were in one commitment, opened at multiple rounds (one per chunk)
    let quotient_openings = values_iter.next().unwrap();
    let quotient_chunks: Vec<Vec<Challenge<SC>>> = quotient_openings
        .iter()
        .map(|round| round[0].clone())
        .collect();

    Proof {
        main_commit,
        aux_commit,
        quotient_commit,
        main_local,
        main_next,
        aux_local,
        aux_next,
        quotient_chunks,
        opening_proof,
        log_degree,
    }
}

/// Compute quotient polynomial values by evaluating constraints on the quotient domain.
#[instrument(skip_all)]
fn compute_quotient_values<SC, A, M>(
    air: &A,
    trace_domain: crate::Domain<SC>,
    quotient_domain: crate::Domain<SC>,
    main_on_quotient: &M,
    _aux_on_quotient: Option<&M>,
    alpha: Challenge<SC>,
    _public_values: &[Val<SC>],
) -> Vec<Challenge<SC>>
where
    SC: crate::StarkGenericConfig,
    Val<SC>: PackedField,
    A: MultiTraceAir<Val<SC>, Challenge<SC>> + for<'a> Air<ProverFolder<'a, SC>>,
    M: p3_matrix::Matrix<Val<SC>> + Sync,
{
    let quotient_size = quotient_domain.size();
    let width_main = main_on_quotient.width();
    let _width_aux = 0; // TODO: Implement proper aux trace handling

    // Compute selectors
    let selectors = trace_domain.selectors_on_coset(quotient_domain);

    // Calculate step size between consecutive trace points in quotient domain LDE
    // quotient_domain is quotient_degree times larger than trace_domain
    let log_quotient_degree =
        p3_util::log2_strict_usize(quotient_size) - p3_util::log2_strict_usize(trace_domain.size());
    let next_step = 1 << log_quotient_degree;

    // Evaluate constraints at each point in quotient domain
    // For simplicity, we'll do this in a single-threaded manner
    // TODO: Add parallel evaluation
    let mut quotient_values = Vec::with_capacity(quotient_size);

    // First pass: count constraints by doing a dry run on first point
    let main_local: Vec<_> = main_on_quotient.row_slice(0).unwrap().to_vec();
    let main_next: Vec<_> = main_on_quotient
        .row_slice(next_step % quotient_size)
        .unwrap()
        .to_vec();
    let main_view =
        p3_matrix::dense::RowMajorMatrix::new([main_local, main_next].concat(), width_main);
    let aux_view = p3_matrix::dense::RowMajorMatrix::new(vec![], 0);

    // Create dummy alpha powers for counting (won't be used, just need something)
    let dummy_alpha_powers = vec![SC::Challenge::ZERO; 100];
    let mut constraint_counter = ProverFolder {
        main: main_view.as_view(),
        aux: aux_view.as_view(),
        is_first_row: selectors.is_first_row[0],
        is_last_row: selectors.is_last_row[0],
        is_transition: selectors.is_transition[0],
        alpha_powers: &dummy_alpha_powers,
        accumulator: SC::Challenge::ZERO,
        constraint_index: 0,
    };
    air.eval(&mut constraint_counter);
    let constraint_count = constraint_counter.constraint_index;

    // Compute exact number of alpha powers and reverse
    let mut alpha_powers: Vec<Challenge<SC>> = Vec::with_capacity(constraint_count);
    let mut power = SC::Challenge::ONE;
    for _ in 0..constraint_count {
        alpha_powers.push(power);
        power *= alpha;
    }
    alpha_powers.reverse();

    for i in 0..quotient_size {
        let is_first_row = selectors.is_first_row[i];
        let is_last_row = selectors.is_last_row[i];
        let is_transition = selectors.is_transition[i];
        let inv_vanishing = selectors.inv_vanishing[i];

        // Get local and next row values
        // Next row is next_step away, not just i+1, because quotient domain LDE
        // interleaves trace points with intermediate evaluation points
        let main_local: Vec<_> = main_on_quotient.row_slice(i).unwrap().to_vec();
        let main_next_idx = (i + next_step) % quotient_size;
        let main_next: Vec<_> = main_on_quotient.row_slice(main_next_idx).unwrap().to_vec();

        let main_view =
            p3_matrix::dense::RowMajorMatrix::new([main_local, main_next].concat(), width_main);

        // TODO: Implement proper aux trace handling
        // For now, use empty aux view
        let aux_view = p3_matrix::dense::RowMajorMatrix::new(vec![], 0);

        // Evaluate constraints
        let mut folder = ProverFolder {
            main: main_view.as_view(),
            aux: aux_view.as_view(),
            is_first_row,
            is_last_row,
            is_transition,
            alpha_powers: &alpha_powers,
            accumulator: SC::Challenge::ZERO,
            constraint_index: 0,
        };

        air.eval(&mut folder);

        // quotient(x) = constraints(x) / Z_H(x)
        let quotient_value = folder.accumulator * inv_vanishing;

        // Debug: Check if we're getting reasonable values
        if i < 3 {
            tracing::debug!(
                "Point {}: constraints={:?}, inv_van={:?}, quotient={:?}",
                i,
                folder.accumulator,
                inv_vanishing,
                quotient_value
            );
        }

        quotient_values.push(quotient_value);
    }

    quotient_values
}
