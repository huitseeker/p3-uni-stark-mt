//! AIR trait extensions for multi-trace proving

use p3_air::BaseAir;
use p3_field::{ExtensionField, Field};
use p3_matrix::dense::RowMajorMatrix;

/// Trait for AIRs that can build auxiliary trace columns.
///
/// The auxiliary trace is built after the main trace has been committed and challenges
/// have been sampled. This enables patterns like LogUp lookup arguments where the
/// auxiliary columns (e.g., running sums) depend on random challenges.
///
/// # Example: LogUp Lookup
///
/// ```ignore
/// struct MyAir;
///
/// impl<F: Field, EF: ExtensionField<F>> AuxTraceBuilder<F, EF> for MyAir {
///     fn aux_width(&self) -> usize {
///         1 // One running sum column
///     }
///
///     fn num_challenges(&self) -> usize {
///         2 // α and β for LogUp
///     }
///
///     fn build_aux_trace(
///         &self,
///         main_trace: &RowMajorMatrix<F>,
///         challenges: &[EF],
///     ) -> RowMajorMatrix<EF> {
///         let (alpha, beta) = (challenges[0], challenges[1]);
///         // Build LogUp running sum...
///     }
/// }
/// ```
pub trait AuxTraceBuilder<F: Field, EF: ExtensionField<F>>: BaseAir<F> + Sync {
    /// Number of auxiliary trace columns.
    ///
    /// Returns 0 for AIRs without auxiliary traces (single-phase proving).
    fn aux_width(&self) -> usize {
        0
    }

    /// Number of random challenge elements needed to build the auxiliary trace.
    ///
    /// Returns 0 for AIRs without auxiliary traces.
    fn num_challenges(&self) -> usize {
        0
    }

    /// Build the auxiliary trace from the main trace and challenges.
    ///
    /// # Arguments
    /// - `main_trace`: The main execution trace (already committed)
    /// - `challenges`: Random challenges sampled after main trace commitment
    ///
    /// # Returns
    /// A matrix of auxiliary trace columns, with:
    /// - Width: [`aux_width()`](Self::aux_width)
    /// - Height: Same as `main_trace.height()`
    ///
    /// # Panics
    /// - If called when `aux_width() == 0`
    /// - If `challenges.len() != num_challenges()`
    fn build_aux_trace(
        &self,
        main_trace: &RowMajorMatrix<F>,
        challenges: &[EF],
    ) -> RowMajorMatrix<EF> {
        let _ = (main_trace, challenges);
        panic!("build_aux_trace called but aux_width() is 0")
    }
}

/// Marker trait for AIRs that can be proven with this crate.
///
/// This is automatically implemented for any type that implements both:
/// - [`BaseAir<F>`]
/// - [`AuxTraceBuilder<F, EF>`]
pub trait MultiTraceAir<F: Field, EF: ExtensionField<F>>:
    BaseAir<F> + AuxTraceBuilder<F, EF>
{
}

// Blanket implementation
impl<F, EF, T> MultiTraceAir<F, EF> for T
where
    F: Field,
    EF: ExtensionField<F>,
    T: BaseAir<F> + AuxTraceBuilder<F, EF>,
{
}
