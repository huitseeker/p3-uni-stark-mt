//! Configuration types for multi-trace STARK

use p3_challenger::{CanObserve, CanSample, FieldChallenger};
use p3_commit::{Pcs, PolynomialSpace};
use p3_field::ExtensionField;

/// Domain type from the PCS
pub type Domain<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Domain;

/// Base field value - derived from the PCS's polynomial space
pub type Val<SC> = <Domain<SC> as PolynomialSpace>::Val;

/// Packed base field value
pub type PackedVal<SC> =
    <<SC as StarkGenericConfig>::Challenge as ExtensionField<Val<SC>>>::ExtensionPacking;

/// Challenge type
pub type Challenge<SC> = <SC as StarkGenericConfig>::Challenge;

/// Packed challenge type
pub type PackedChallenge<SC> =
    <<SC as StarkGenericConfig>::Challenge as ExtensionField<Val<SC>>>::ExtensionPacking;

/// Challenger type
pub type Challenger<SC> = <SC as StarkGenericConfig>::Challenger;

/// Generic STARK configuration trait matching upstream p3-uni-stark pattern
pub trait StarkGenericConfig {
    /// Polynomial commitment scheme
    type Pcs: Pcs<Self::Challenge, Self::Challenger>;

    /// Extension field for challenges
    type Challenge: ExtensionField<Val<Self>>;

    /// Fiat-Shamir challenger
    type Challenger: FieldChallenger<Val<Self>>
        + CanObserve<<Self::Pcs as Pcs<Self::Challenge, Self::Challenger>>::Commitment>
        + CanSample<Self::Challenge>;

    /// Get the PCS instance
    fn pcs(&self) -> &Self::Pcs;

    /// Create a new challenger for Fiat-Shamir
    fn initialise_challenger(&self) -> Self::Challenger;

    /// Returns 1 if the PCS is zero-knowledge, 0 otherwise
    fn is_zk(&self) -> usize {
        Self::Pcs::ZK as usize
    }
}

/// Concrete STARK configuration
#[derive(Debug)]
pub struct StarkConfig<Pcs, Challenge, Challenger> {
    /// The PCS used to commit polynomials
    pub pcs: Pcs,
    /// Initial challenger state
    pub challenger: Challenger,
    _phantom: core::marker::PhantomData<Challenge>,
}

impl<Pcs, Challenge, Challenger> StarkConfig<Pcs, Challenge, Challenger> {
    pub const fn new(pcs: Pcs, challenger: Challenger) -> Self {
        Self {
            pcs,
            challenger,
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<P, Challenge, C> StarkGenericConfig for StarkConfig<P, Challenge, C>
where
    Challenge: ExtensionField<<P::Domain as PolynomialSpace>::Val>,
    P: Pcs<Challenge, C>,
    C: FieldChallenger<<P::Domain as PolynomialSpace>::Val>
        + CanObserve<P::Commitment>
        + CanSample<Challenge>
        + Clone,
{
    type Pcs = P;
    type Challenge = Challenge;
    type Challenger = C;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn initialise_challenger(&self) -> Self::Challenger {
        self.challenger.clone()
    }
}
