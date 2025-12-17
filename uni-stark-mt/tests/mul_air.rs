//! Test for multiplication AIR with different constraint degrees

use itertools::Itertools;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing};
use p3_fri::{create_test_fri_params, TwoAdicFriPcs};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark_mt::{prove, verify, AuxTraceBuilder, StarkConfig};
use rand::distr::{Distribution, StandardUniform};
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

/// How many `a * b = c` operations to do per row in the AIR.
const REPETITIONS: usize = 20;
const TRACE_WIDTH: usize = REPETITIONS * 3;

/// Multiplication AIR: asserts a^(degree-1) * b = c
pub struct MulAir {
    degree: u64,
    uses_boundary_constraints: bool,
    uses_transition_constraints: bool,
}

impl Default for MulAir {
    fn default() -> Self {
        Self {
            degree: 3,
            uses_boundary_constraints: true,
            uses_transition_constraints: true,
        }
    }
}

impl MulAir {
    pub fn random_valid_trace<F: Field>(&self, rows: usize) -> RowMajorMatrix<F>
    where
        StandardUniform: Distribution<F>,
    {
        let mut rng = SmallRng::seed_from_u64(1);
        let mut trace_values = F::zero_vec(rows * TRACE_WIDTH);
        for (i, (a, b, c)) in trace_values.iter_mut().tuples().enumerate() {
            let row = i / REPETITIONS;
            *a = if self.uses_transition_constraints {
                F::from_usize(i)
            } else {
                rng.random()
            };
            *b = if self.uses_boundary_constraints && row == 0 {
                a.square() + F::ONE
            } else {
                rng.random()
            };
            *c = a.exp_u64(self.degree - 1) * *b;
        }
        RowMajorMatrix::new(trace_values, TRACE_WIDTH)
    }
}

impl<F> BaseAir<F> for MulAir {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }
}

impl<AB: AirBuilder> Air<AB> for MulAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let main_local = main.row_slice(0).expect("Matrix is empty?");
        let main_next = main.row_slice(1).expect("Matrix only has 1 row?");

        for i in 0..REPETITIONS {
            let start = i * 3;
            let a = main_local[start].clone();
            let b = main_local[start + 1].clone();
            let c = main_local[start + 2].clone();
            builder.assert_zero(a.clone().into().exp_u64(self.degree - 1) * b.clone() - c);
            if self.uses_boundary_constraints {
                builder
                    .when_first_row()
                    .assert_eq(a.clone() * a.clone() + AB::Expr::ONE, b);
            }
            if self.uses_transition_constraints {
                let next_a = main_next[start].clone();
                builder
                    .when_transition()
                    .assert_eq(a + AB::Expr::from_u8(REPETITIONS as u8), next_a);
            }
        }
    }
}

// MulAir has no auxiliary trace, so we implement the minimal AuxTraceBuilder
impl<F, EF> AuxTraceBuilder<F, EF> for MulAir
where
    F: Field,
    EF: ExtensionField<F>,
{
    fn aux_width(&self) -> usize {
        0 // No auxiliary columns
    }

    fn num_challenges(&self) -> usize {
        0 // No challenges needed
    }

    fn build_aux_trace(&self, _main: &RowMajorMatrix<F>, _challenges: &[EF]) -> RowMajorMatrix<EF> {
        // Return empty matrix
        RowMajorMatrix::new(vec![], 0)
    }
}

fn create_test_config(
    _log_n: usize,
) -> StarkConfig<
    TwoAdicFriPcs<
        BabyBear,
        Radix2DitParallel<BabyBear>,
        MerkleTreeMmcs<
            <BabyBear as Field>::Packing,
            <BabyBear as Field>::Packing,
            PaddingFreeSponge<Poseidon2BabyBear<16>, 16, 8, 8>,
            TruncatedPermutation<Poseidon2BabyBear<16>, 2, 8, 16>,
            8,
        >,
        ExtensionMmcs<
            BabyBear,
            BinomialExtensionField<BabyBear, 4>,
            MerkleTreeMmcs<
                <BabyBear as Field>::Packing,
                <BabyBear as Field>::Packing,
                PaddingFreeSponge<Poseidon2BabyBear<16>, 16, 8, 8>,
                TruncatedPermutation<Poseidon2BabyBear<16>, 2, 8, 16>,
                8,
            >,
        >,
    >,
    BinomialExtensionField<BabyBear, 4>,
    DuplexChallenger<BabyBear, Poseidon2BabyBear<16>, 16, 8>,
> {
    type Val = BabyBear;
    type Challenge = BinomialExtensionField<Val, 4>;
    type Perm = Poseidon2BabyBear<16>;

    let mut rng = SmallRng::seed_from_u64(1);
    let perm = Perm::new_from_rng_128(&mut rng);

    type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
    let hash = MyHash::new(perm.clone());

    type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
    let compress = MyCompress::new(perm.clone());

    type ValMmcs =
        MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 8>;
    let val_mmcs = ValMmcs::new(hash, compress);

    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    type Dft = Radix2DitParallel<Val>;
    let dft = Dft::default();

    type Challenger = DuplexChallenger<Val, Perm, 16, 8>;

    // Use the helper function to create FRI parameters
    // log_final_poly_len should be small (typically 0-3)
    let fri_params = create_test_fri_params(challenge_mmcs, 2);

    type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);

    StarkConfig::new(pcs, challenger)
}

#[test]
fn test_mul_air_deg2() {
    let log_n = 5;
    let config = create_test_config(log_n);

    let air = MulAir {
        degree: 2,
        ..Default::default()
    };

    let trace = air.random_valid_trace(1 << log_n);
    let public_values = vec![];

    println!("Generating proof for degree 2...");
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
fn test_mul_air_deg3() {
    let log_n = 5;
    let config = create_test_config(log_n);

    let air = MulAir {
        degree: 3,
        ..Default::default()
    };

    let trace = air.random_valid_trace(1 << log_n);
    let public_values = vec![];

    println!("Generating proof for degree 3...");
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
fn test_mul_air_deg4() {
    let log_n = 4;
    let config = create_test_config(log_n);

    let air = MulAir {
        degree: 4,
        ..Default::default()
    };

    let trace = air.random_valid_trace(1 << log_n);
    let public_values = vec![];

    println!("Generating proof for degree 4...");
    let proof = prove(&config, &air, trace, &public_values);
    println!(
        "Proof generated. Quotient chunks: {}",
        proof.quotient_chunks.len()
    );

    println!("Verifying proof...");
    verify(&config, &air, &proof, &public_values).expect("verification failed");
    println!("Verification successful!");
}
