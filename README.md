# p3-md

Multi-trace STARK prover for Plonky3 with minimal abstractions.

This crate extends Plonky3's univariate STARK framework to support two-phase proving. The main trace commits first, then challenges are sampled, then an auxiliary trace is built and committed before quotient computation.

## Flow

Standard univariate STARK:
```
Main trace → Commit → Quotient → Open
```

This crate:
```
Main trace → Commit → Sample challenges → Build auxiliary trace → Commit → Quotient → Open
```

## Traits

Define auxiliary trace requirements:

```rust
pub trait AuxTraceBuilder<F: Field, EF: ExtensionField<F>>: BaseAir<F> {
    fn aux_width(&self) -> usize;
    fn num_challenges(&self) -> usize;
    fn build_aux_trace(
        &self,
        main_trace: &RowMajorMatrix<F>,
        challenges: &[EF],
    ) -> RowMajorMatrix<EF>;
}
```

Evaluate constraints with auxiliary trace access:

```rust
pub trait Air<AB: AirBuilder>: BaseAir<AB::F> {
    fn eval(&self, builder: &mut AB);
}

pub trait AuxBuilder: AirBuilder {
    type EF: ExtensionField<Self::F>;
    type ExprEF: Algebra<Self::Expr> + Algebra<Self::EF>;
    type VarEF: Into<Self::ExprEF> + Copy;

    fn aux(&self) -> &[Self::VarEF];
}
```

## Example

```rust
use p3_uni_stark_mt::{prove, verify, AuxTraceBuilder, AuxBuilder};

struct FibonacciLogUp;

impl AuxTraceBuilder<F, EF> for FibonacciLogUp {
    fn aux_width(&self) -> usize { 1 }
    fn num_challenges(&self) -> usize { 2 }

    fn build_aux_trace(&self, main: &RowMajorMatrix<F>, challenges: &[EF])
        -> RowMajorMatrix<EF>
    {
        let (alpha, beta) = (challenges[0], challenges[1]);
        // Build LogUp running sum column
    }
}

impl<AB: AuxBuilder> Air<AB> for FibonacciLogUp {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let aux = builder.aux();

        builder.when_transition()
            .assert_eq(main.row(2), main.row(0) + main.row(1));

        // LogUp constraints using aux[0]
    }
}

let proof = prove(&config, &air, main_trace, &public_values);
verify(&config, &air, &proof, &public_values)?;
```

## Design

Uses standard Plonky3 crates with no modifications. Simple trait extensions without complex machinery. Works with single-phase AIRs that have no auxiliary trace and two-phase AIRs with one auxiliary phase. Supports logarithmic derivative lookup arguments.

## Comparison

| Approach | Dependencies | Abstraction | Multi-AIR | Multi-Phase |
|----------|--------------|-------------|-----------|-------------|
| This crate | Upstream P3 | Minimal | No | 1 aux phase |
| 0xMiden/Plonky3 | Modified P3 | Low | No | 1 aux phase |
| han0110/uni-stark-ext | Upstream P3 | Medium | Yes | 1 LogUp phase |
| OpenVM/stark-backend | Upstream P3 | High | Yes | Arbitrary |

This crate does not support multiple AIRs in one proof, multiple challenge phases, or cross-AIR interactions. Use OpenVM stark-backend or han0110 InteractionBuilder for those cases.

## License

Licensed under either Apache License 2.0 or MIT license at your option.
