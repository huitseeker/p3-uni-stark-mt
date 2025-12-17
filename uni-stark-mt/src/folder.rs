//! Constraint folders for prover and verifier

use p3_air::{AirBuilder, ExtensionBuilder};
use p3_field::PackedField;
use p3_matrix::dense::RowMajorMatrixView;

use crate::{Challenge, Val};

/// Builder for evaluating constraints during proving.
///
/// This folder accumulates constraints using random challenges, computing:
/// `C_0 + α·C_1 + α²·C_2 + ...`
pub struct ProverFolder<'a, SC: crate::StarkGenericConfig>
where
    Val<SC>: PackedField,
{
    /// Main trace values (local and next rows, packed)
    pub main: RowMajorMatrixView<'a, Val<SC>>,

    /// Auxiliary trace values (local and next rows, packed)
    /// Empty if no auxiliary trace
    pub aux: RowMajorMatrixView<'a, Challenge<SC>>,

    /// Selector: 1 on first row, 0 elsewhere
    pub is_first_row: Val<SC>,

    /// Selector: 1 on last row, 0 elsewhere
    pub is_last_row: Val<SC>,

    /// Selector: 1 on all rows except last, 0 on last
    pub is_transition: Val<SC>,

    /// Powers of α for constraint randomization
    pub alpha_powers: &'a [Challenge<SC>],

    /// Accumulated constraint value
    pub accumulator: Challenge<SC>,

    /// Current constraint index
    pub constraint_index: usize,
}

impl<'a, SC> AirBuilder for ProverFolder<'a, SC>
where
    SC: crate::StarkGenericConfig,
    Val<SC>: PackedField,
{
    type F = Val<SC>;
    type Expr = Val<SC>;
    type Var = Val<SC>;
    type M = RowMajorMatrixView<'a, Val<SC>>;

    fn main(&self) -> Self::M {
        self.main
    }

    fn is_first_row(&self) -> Self::Expr {
        self.is_first_row
    }

    fn is_last_row(&self) -> Self::Expr {
        self.is_last_row
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        assert_eq!(size, 2, "Only window size 2 is supported");
        self.is_transition
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        let x = x.into();
        let alpha = self.alpha_powers[self.constraint_index];
        self.accumulator += alpha * x;
        self.constraint_index += 1;
    }
}

impl<'a, SC> ExtensionBuilder for ProverFolder<'a, SC>
where
    SC: crate::StarkGenericConfig,
    Val<SC>: PackedField,
{
    type EF = Challenge<SC>;
    type ExprEF = Challenge<SC>;
    type VarEF = Challenge<SC>;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        let x = x.into();
        let alpha = self.alpha_powers[self.constraint_index];
        self.accumulator += alpha * x;
        self.constraint_index += 1;
    }
}

/// Extension trait for accessing auxiliary trace in constraints.
pub trait AuxBuilder: ExtensionBuilder {
    /// Matrix type for auxiliary trace
    type MAux;

    /// Access the auxiliary trace columns
    fn aux(&self) -> Self::MAux;
}

impl<'a, SC> AuxBuilder for ProverFolder<'a, SC>
where
    SC: crate::StarkGenericConfig,
    Val<SC>: PackedField,
{
    type MAux = RowMajorMatrixView<'a, Challenge<SC>>;

    fn aux(&self) -> Self::MAux {
        self.aux
    }
}

/// Builder for verifying constraints.
///
/// Similar to [`ProverFolder`] but operates on opened polynomial values rather than
/// full trace matrices.
pub struct VerifierFolder<'a, SC: crate::StarkGenericConfig> {
    /// Main trace values (local row)
    pub main_local: &'a [Challenge<SC>],

    /// Main trace values (next row)
    pub main_next: &'a [Challenge<SC>],

    /// Auxiliary trace values (local row)
    pub aux_local: &'a [Challenge<SC>],

    /// Auxiliary trace values (next row)
    pub aux_next: &'a [Challenge<SC>],

    /// Selector: 1 on first row, 0 elsewhere
    pub is_first_row: Challenge<SC>,

    /// Selector: 1 on last row, 0 elsewhere
    pub is_last_row: Challenge<SC>,

    /// Selector: 1 on all rows except last, 0 on last
    pub is_transition: Challenge<SC>,

    /// Randomness for combining constraints
    pub alpha: Challenge<SC>,

    /// Accumulated constraint value
    pub accumulator: Challenge<SC>,
}

/// Simple view for verifier (just vectors of challenges)
#[derive(Copy, Clone)]
pub struct VerifierView<'a, EF> {
    local: &'a [EF],
    next: &'a [EF],
}

impl<'a, EF: Copy> VerifierView<'a, EF> {
    pub fn new(local: &'a [EF], next: &'a [EF]) -> Self {
        Self { local, next }
    }

    pub fn get_local(&self, col: usize) -> EF {
        self.local[col]
    }

    pub fn get_next(&self, col: usize) -> EF {
        self.next[col]
    }
}

// Implement Matrix trait for VerifierView
impl<'a, EF: Copy + Send + Sync> p3_matrix::Matrix<EF> for VerifierView<'a, EF> {
    fn width(&self) -> usize {
        self.local.len()
    }

    fn height(&self) -> usize {
        2 // local and next
    }

    unsafe fn get_unchecked(&self, row: usize, col: usize) -> EF {
        match row {
            0 => *self.local.get_unchecked(col),
            1 => *self.next.get_unchecked(col),
            _ => core::hint::unreachable_unchecked(),
        }
    }

    fn row_slice(&self, r: usize) -> Option<&[EF]> {
        match r {
            0 => Some(self.local),
            1 => Some(self.next),
            _ => None,
        }
    }
}

impl<'a, SC> AirBuilder for VerifierFolder<'a, SC>
where
    SC: crate::StarkGenericConfig,
{
    type F = Val<SC>;
    type Expr = Challenge<SC>;
    type Var = Challenge<SC>;
    type M = VerifierView<'a, Challenge<SC>>;

    fn main(&self) -> Self::M {
        VerifierView::new(self.main_local, self.main_next)
    }

    fn is_first_row(&self) -> Self::Expr {
        self.is_first_row
    }

    fn is_last_row(&self) -> Self::Expr {
        self.is_last_row
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        assert_eq!(size, 2, "Only window size 2 is supported");
        self.is_transition
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.accumulator = self.accumulator * self.alpha + x.into();
    }
}

impl<'a, SC> ExtensionBuilder for VerifierFolder<'a, SC>
where
    SC: crate::StarkGenericConfig,
{
    type EF = Challenge<SC>;
    type ExprEF = Challenge<SC>;
    type VarEF = Challenge<SC>;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        self.accumulator = self.accumulator * self.alpha + x.into();
    }
}

impl<'a, SC> AuxBuilder for VerifierFolder<'a, SC>
where
    SC: crate::StarkGenericConfig,
{
    type MAux = VerifierView<'a, Challenge<SC>>;

    fn aux(&self) -> Self::MAux {
        VerifierView::new(self.aux_local, self.aux_next)
    }
}
