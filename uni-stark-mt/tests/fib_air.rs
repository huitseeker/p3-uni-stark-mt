//! Basic Fibonacci AIR test for multi-trace STARK
//!
//! This is a simplified version that tests the core proving/verification without
//! auxiliary traces or public values (to be added later).

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_fri::{create_test_fri_params, TwoAdicFriPcs};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark_mt::{prove, verify, AuxTraceBuilder, StarkConfig};
use rand::rngs::SmallRng;
use rand::SeedableRng;

/// Simple Fibonacci AIR without public values
pub struct FibonacciAir {
    /// Expected final value (hardcoded in constraints for now)
    pub expected_final: u32,
}

impl<F> BaseAir<F> for FibonacciAir {
    fn width(&self) -> usize {
        NUM_FIBONACCI_COLS
    }
}

// Implement AuxTraceBuilder with no auxiliary trace (single-phase proving)
impl<F: Field, EF> AuxTraceBuilder<F, EF> for FibonacciAir
where
    EF: p3_field::ExtensionField<F>,
{
    fn aux_width(&self) -> usize {
        0 // No auxiliary trace
    }

    fn num_challenges(&self) -> usize {
        0 // No challenges needed
    }
}

impl<AB: AirBuilder> Air<AB> for FibonacciAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        let (local, next) = (
            main.row_slice(0).expect("Matrix is empty?"),
            main.row_slice(1).expect("Matrix only has 1 row?"),
        );
        let local: &FibonacciRow<AB::Var> = (*local).borrow();
        let next: &FibonacciRow<AB::Var> = (*next).borrow();

        let mut when_first_row = builder.when_first_row();

        // Constrain first row: (0, 1)
        when_first_row.assert_zero(local.left.clone());
        when_first_row.assert_eq(local.right.clone(), AB::Expr::from(AB::F::ONE));

        let mut when_transition = builder.when_transition();

        // Transition constraints: a' = b, b' = a + b
        when_transition.assert_eq(local.right.clone(), next.left.clone());
        when_transition.assert_eq(local.left.clone() + local.right.clone(), next.right.clone());

        // TODO: Add final value constraint when we support public values
        // For now, we just verify the Fibonacci recurrence relation
    }
}

pub fn generate_trace_rows<F: PrimeField64>(a: u64, b: u64, n: usize) -> RowMajorMatrix<F> {
    assert!(n.is_power_of_two());

    let mut trace = RowMajorMatrix::new(F::zero_vec(n * NUM_FIBONACCI_COLS), NUM_FIBONACCI_COLS);

    let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<FibonacciRow<F>>() };
    assert!(prefix.is_empty(), "Alignment should match");
    assert!(suffix.is_empty(), "Alignment should match");
    assert_eq!(rows.len(), n);

    rows[0] = FibonacciRow::new(F::from_u64(a), F::from_u64(b));

    for i in 1..n {
        rows[i].left = rows[i - 1].right;
        rows[i].right = rows[i - 1].left + rows[i - 1].right;
    }

    trace
}

const NUM_FIBONACCI_COLS: usize = 2;

pub struct FibonacciRow<F> {
    pub left: F,
    pub right: F,
}

impl<F> FibonacciRow<F> {
    const fn new(left: F, right: F) -> Self {
        Self { left, right }
    }
}

impl<F> Borrow<FibonacciRow<F>> for [F] {
    fn borrow(&self) -> &FibonacciRow<F> {
        debug_assert_eq!(self.len(), NUM_FIBONACCI_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<FibonacciRow<F>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

// Type aliases for test configuration
type Val = BabyBear;
type Perm = Poseidon2BabyBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 8>;
type Challenge = BinomialExtensionField<Val, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
type Dft = Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;

#[test]
fn test_fibonacci_basic() {
    let mut rng = SmallRng::seed_from_u64(1);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();

    let n = 1 << 3; // 8 rows
    let trace = generate_trace_rows::<Val>(0, 1, n);

    let fri_params = create_test_fri_params(challenge_mmcs, 2);
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);
    let config = MyConfig::new(pcs, challenger);

    let air = FibonacciAir {
        expected_final: 21, // 8th Fibonacci number
    };

    // Empty public values for now
    let public_values = vec![];

    println!("Generating proof...");
    let proof = prove(&config, &air, trace, &public_values);
    println!(
        "Proof generated. Quotient chunks: {}",
        proof.quotient_chunks.len()
    );
    println!("Verifying proof...");
    verify(&config, &air, &proof, &public_values).expect("verification failed");
    println!("Verification successful!");
}

#[test]
fn test_fibonacci_one_row() {
    let mut rng = SmallRng::seed_from_u64(1);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();

    let n = 1; // Single row
    let trace = generate_trace_rows::<Val>(0, 1, n);

    let fri_params = create_test_fri_params(challenge_mmcs, 0);
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);
    let config = MyConfig::new(pcs, challenger);

    let air = FibonacciAir { expected_final: 1 };

    let public_values = vec![];

    let proof = prove(&config, &air, trace, &public_values);
    verify(&config, &air, &proof, &public_values).expect("verification failed");
}
