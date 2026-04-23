use std::borrow::Cow;
use std::cell::Cell;

use libafl::{
    corpus::CorpusId,
    mutators::{MutationResult, Mutator},
    state::HasRand,
    Error,
};
use libafl_bolts::{rands::Rand, Named};
use pe_mutator_core::{
    core::{
        plan_executable_chunk_assembly_mutation as core_plan_executable, ArchitectureMutations,
        DataDirectoryEntryMutations, EntryPointMutations, ExecutableChunkAssemblyMutations,
        ExecutableChunkMutationPlan, OverlayMutations, RawMutationResult,
        ResourceDirectoryMutations, SectionBodyMutations, SectionCountMutations,
        SectionHeaderMutations,
    },
    error::{Error as CoreError, ErrorKind as CoreErrorKind},
    mutations::{ExportDirectoryMutations, PeSizeBudget},
    pe::{PeInput, PeSizeLimits},
};

use crate::rng_wrapper::LibAFLRng;

thread_local! {
    static EXPORT_DIRECTORY_LOCKED: Cell<bool> = const { Cell::new(false) };
}

pub(crate) fn reset_iteration_mutation_guards() {
    EXPORT_DIRECTORY_LOCKED.with(|locked| locked.set(false));
}

fn export_directory_locked() -> bool {
    EXPORT_DIRECTORY_LOCKED.with(Cell::get)
}

fn lock_export_directory() {
    EXPORT_DIRECTORY_LOCKED.with(|locked| locked.set(true));
}

fn raw_to_libafl(result: RawMutationResult) -> MutationResult {
    match result {
        RawMutationResult::Mutated => MutationResult::Mutated,
        RawMutationResult::Skipped => MutationResult::Skipped,
    }
}

fn core_to_libafl_error(err: CoreError) -> Error {
    Error::illegal_argument(err.to_string())
}

fn recover_mutation_error(err: CoreError) -> Result<MutationResult, Error> {
    match err.kind() {
        CoreErrorKind::InvalidInput
        | CoreErrorKind::Parse
        | CoreErrorKind::Layout
        | CoreErrorKind::Assembly
        | CoreErrorKind::Encoding => Ok(MutationResult::Skipped),
        CoreErrorKind::Internal => Err(core_to_libafl_error(err)),
    }
}

fn raw_result_to_libafl(
    result: Result<RawMutationResult, CoreError>,
) -> Result<MutationResult, Error> {
    match result {
        Ok(result) => Ok(raw_to_libafl(result)),
        Err(err) => recover_mutation_error(err),
    }
}

pub struct ArchitectureMutator {
    max_materialized_size: Option<usize>,
}

impl ArchitectureMutator {
    pub fn new() -> Self {
        Self {
            max_materialized_size: None,
        }
    }

    pub fn with_max_materialized_size(max_materialized_size: Option<usize>) -> Self {
        Self {
            max_materialized_size,
        }
    }
}

impl<S> Mutator<PeInput, S> for ArchitectureMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut PeInput) -> Result<MutationResult, Error> {
        let mut rng = LibAFLRng::new(state.rand_mut());
        let mut budget = match PeSizeBudget::from_input(
            input,
            PeSizeLimits {
                max_materialized_size: self.max_materialized_size,
                max_serialized_size: None,
            },
        ) {
            Ok(budget) => budget,
            Err(err) => return recover_mutation_error(err),
        };
        raw_result_to_libafl(ArchitectureMutations::random_mutation_with_budget(
            input,
            &mut rng,
            &mut budget,
        ))
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for ArchitectureMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("ArchitectureMutator")
    }
}

pub struct SectionCountMutator {
    max_materialized_size: Option<usize>,
}

impl SectionCountMutator {
    pub fn new() -> Self {
        Self {
            max_materialized_size: None,
        }
    }

    pub fn with_max_materialized_size(max_materialized_size: Option<usize>) -> Self {
        Self {
            max_materialized_size,
        }
    }
}

impl<S> Mutator<PeInput, S> for SectionCountMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut PeInput) -> Result<MutationResult, Error> {
        let mut rng = LibAFLRng::new(state.rand_mut());
        let mut budget = match PeSizeBudget::from_input(
            input,
            PeSizeLimits {
                max_materialized_size: self.max_materialized_size,
                max_serialized_size: None,
            },
        ) {
            Ok(budget) => budget,
            Err(err) => return recover_mutation_error(err),
        };
        raw_result_to_libafl(SectionCountMutations::random_mutation_with_budget(
            input,
            &mut rng,
            &mut budget,
        ))
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for SectionCountMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("SectionCountMutator")
    }
}

pub struct SectionHeaderMutator;

impl<S> Mutator<PeInput, S> for SectionHeaderMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut PeInput) -> Result<MutationResult, Error> {
        let mut rng = LibAFLRng::new(state.rand_mut());
        Ok(raw_to_libafl(SectionHeaderMutations::random_mutation(
            input, &mut rng,
        )))
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for SectionHeaderMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("SectionHeaderMutator")
    }
}

pub struct SectionBodyMutator {
    max_materialized_size: Option<usize>,
}

impl SectionBodyMutator {
    pub fn new() -> Self {
        Self {
            max_materialized_size: None,
        }
    }

    pub fn with_max_materialized_size(max_materialized_size: Option<usize>) -> Self {
        Self {
            max_materialized_size,
        }
    }
}

impl<S> Mutator<PeInput, S> for SectionBodyMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut PeInput) -> Result<MutationResult, Error> {
        let mut rng = LibAFLRng::new(state.rand_mut());
        let mut budget = match PeSizeBudget::from_input(
            input,
            PeSizeLimits {
                max_materialized_size: self.max_materialized_size,
                max_serialized_size: None,
            },
        ) {
            Ok(budget) => budget,
            Err(err) => return recover_mutation_error(err),
        };
        Ok(raw_to_libafl(
            SectionBodyMutations::random_mutation_with_budget(input, &mut rng, &mut budget),
        ))
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

pub struct EntryPointMutator {
    max_materialized_size: Option<usize>,
}

impl EntryPointMutator {
    pub fn new() -> Self {
        Self {
            max_materialized_size: None,
        }
    }

    pub fn with_max_materialized_size(max_materialized_size: Option<usize>) -> Self {
        Self {
            max_materialized_size,
        }
    }
}

impl<S> Mutator<PeInput, S> for EntryPointMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut PeInput) -> Result<MutationResult, Error> {
        let mut rng = LibAFLRng::new(state.rand_mut());
        let mut budget = match PeSizeBudget::from_input(
            input,
            PeSizeLimits {
                max_materialized_size: self.max_materialized_size,
                max_serialized_size: None,
            },
        ) {
            Ok(budget) => budget,
            Err(err) => return recover_mutation_error(err),
        };
        raw_result_to_libafl(EntryPointMutations::random_mutation_with_budget(
            input,
            &mut rng,
            &mut budget,
        ))
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for SectionBodyMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("SectionBodyMutator")
    }
}

impl Named for EntryPointMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("EntryPointMutator")
    }
}

pub struct ExecutableChunkAssemblyMutator {
    max_materialized_size: Option<usize>,
}

impl ExecutableChunkAssemblyMutator {
    pub fn new() -> Self {
        Self {
            max_materialized_size: None,
        }
    }

    pub fn with_max_materialized_size(max_materialized_size: Option<usize>) -> Self {
        Self {
            max_materialized_size,
        }
    }
}

pub fn plan_executable_chunk_assembly_mutation<R: Rand>(
    rand: &mut R,
    input: &PeInput,
) -> Result<Option<ExecutableChunkMutationPlan>, Error> {
    let mut rng = LibAFLRng::new(rand);
    core_plan_executable(&mut rng, input).map_err(core_to_libafl_error)
}

impl<S> Mutator<PeInput, S> for ExecutableChunkAssemblyMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut PeInput) -> Result<MutationResult, Error> {
        let mut rng = LibAFLRng::new(state.rand_mut());
        let mut budget = match PeSizeBudget::from_input(
            input,
            PeSizeLimits {
                max_materialized_size: self.max_materialized_size,
                max_serialized_size: None,
            },
        ) {
            Ok(budget) => budget,
            Err(err) => return recover_mutation_error(err),
        };
        raw_result_to_libafl(
            ExecutableChunkAssemblyMutations::random_mutation_with_budget(
                input,
                &mut rng,
                &mut budget,
            ),
        )
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for ExecutableChunkAssemblyMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("ExecutableChunkAssemblyMutator")
    }
}

pub struct OverlayMutator {
    max_len: usize,
    max_materialized_size: Option<usize>,
}

impl OverlayMutator {
    pub fn new(max_len: usize) -> Self {
        Self {
            max_len,
            max_materialized_size: None,
        }
    }

    pub fn with_limits(max_len: usize, max_materialized_size: Option<usize>) -> Self {
        Self {
            max_len,
            max_materialized_size,
        }
    }
}

impl<S> Mutator<PeInput, S> for OverlayMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut PeInput) -> Result<MutationResult, Error> {
        let mut rng = LibAFLRng::new(state.rand_mut());
        let mut budget = match PeSizeBudget::from_input(
            input,
            PeSizeLimits {
                max_materialized_size: self.max_materialized_size,
                max_serialized_size: None,
            },
        ) {
            Ok(budget) => budget,
            Err(err) => return recover_mutation_error(err),
        };
        Ok(raw_to_libafl(
            OverlayMutations::random_mutation_with_budget(
                input,
                &mut rng,
                self.max_len,
                &mut budget,
            ),
        ))
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for OverlayMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("OverlayMutator")
    }
}

pub struct DataDirectoryEntryMutator;

impl<S> Mutator<PeInput, S> for DataDirectoryEntryMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut PeInput) -> Result<MutationResult, Error> {
        if export_directory_locked() {
            return Ok(MutationResult::Skipped);
        }

        let mut rng = LibAFLRng::new(state.rand_mut());
        let outcome = DataDirectoryEntryMutations::random_mutation_with_outcome(input, &mut rng);
        if outcome.result == RawMutationResult::Mutated && outcome.touched_export_directory {
            lock_export_directory();
        }
        Ok(raw_to_libafl(outcome.result))
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for DataDirectoryEntryMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("DataDirectoryEntryMutator")
    }
}

pub struct ExportDirectoryMutator;

impl<S> Mutator<PeInput, S> for ExportDirectoryMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut PeInput) -> Result<MutationResult, Error> {
        if export_directory_locked() {
            return Ok(MutationResult::Skipped);
        }

        let mut rng = LibAFLRng::new(state.rand_mut());
        let result = ExportDirectoryMutations::random_mutation(input, &mut rng);
        if result == RawMutationResult::Mutated {
            lock_export_directory();
        }
        Ok(raw_to_libafl(result))
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for ExportDirectoryMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("ExportDirectoryMutator")
    }
}

pub struct ResourceDirectoryMutator;

impl<S> Mutator<PeInput, S> for ResourceDirectoryMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut PeInput) -> Result<MutationResult, Error> {
        let mut rng = LibAFLRng::new(state.rand_mut());
        let result = ResourceDirectoryMutations::random_mutation(input, &mut rng);
        Ok(raw_to_libafl(result))
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for ResourceDirectoryMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("ResourceDirectoryMutator")
    }
}
