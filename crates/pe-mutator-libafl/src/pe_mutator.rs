use std::borrow::Cow;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use libafl::{
    corpus::CorpusId,
    inputs::{BytesInput, HasTargetBytes},
    mutators::{ComposedByMutations, HavocScheduledMutator, MutationResult, Mutator},
    state::HasRand,
    Error,
};
use libafl_bolts::{
    tuples::{tuple_list, tuple_list_type},
    Named,
};
use pe_mutator_core::{
    error::{Error as CoreError, ErrorKind as CoreErrorKind},
    pe::{PeInput, PeSerializationConfig, PeSizeLimits},
    PeMutationCategory, PeMutationCategorySet, PeMutationReport, PeMutator as CorePeMutator,
    PeMutatorConfig,
};

use crate::mutator::{
    reset_iteration_mutation_guards, ArchitectureMutator, DataDirectoryEntryMutator,
    EntryPointMutator, ExecutableChunkAssemblyMutator, ExportDirectoryMutator, OverlayMutator,
    ResourceDirectoryMutator, SectionBodyMutator, SectionCountMutator, SectionHeaderMutator,
};

pub const DEFAULT_OVERLAY_MAX_LEN: usize = 0x1000;

fn core_to_libafl_error(err: CoreError) -> Error {
    Error::illegal_argument(err.to_string())
}

fn write_mutation_report(path: &Path, report: &PeMutationReport) -> Result<(), Error> {
    let mutation_names = if report.selected_mutations.is_empty() {
        "none".to_string()
    } else {
        report
            .selected_mutations
            .iter()
            .map(|kind| kind.name())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let report_text = format!(
        concat!(
            "attempted_mutations: {attempted_mutations}\n",
            "mutated_count: {mutated_count}\n",
            "skipped_count: {skipped_count}\n",
            "any_mutated: {any_mutated}\n",
            "requested_stack_depth: {requested_stack_depth}\n",
            "selected_mutations: {selected_mutations}\n\n"
        ),
        attempted_mutations = report.attempted_count(),
        mutated_count = report.mutated_count,
        skipped_count = report.skipped_count,
        any_mutated = report.any_mutated(),
        requested_stack_depth = report.requested_stack_depth,
        selected_mutations = mutation_names,
    );
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| {
            Error::illegal_argument(format!("failed to open report {}: {err}", path.display()))
        })?;
    file.write_all(report_text.as_bytes()).map_err(|err| {
        Error::illegal_argument(format!("failed to write report {}: {err}", path.display()))
    })
}

#[derive(Debug, Clone, Default)]
pub struct PeMutatorOptions {
    pub reporting: Option<PathBuf>,
    pub max_size: Option<usize>,
}

pub struct PeMutator {
    config: PeMutatorConfig,
    reporting: Option<PathBuf>,
    max_size: Option<usize>,
}

impl PeMutator {
    pub fn new() -> Self {
        Self::with_config(PeMutatorConfig::default())
    }

    pub fn with_config(config: PeMutatorConfig) -> Self {
        Self::with_options(config, PeMutatorOptions::default())
    }

    pub fn with_options(config: PeMutatorConfig, options: PeMutatorOptions) -> Self {
        Self {
            config,
            reporting: options.reporting,
            max_size: options.max_size,
        }
    }

    pub fn reporting_path(&self) -> Option<&Path> {
        self.reporting.as_deref()
    }

    pub fn set_reporting_path<P: Into<PathBuf>>(&mut self, reporting: Option<P>) {
        self.reporting = reporting.map(Into::into);
    }

    pub fn config(&self) -> &PeMutatorConfig {
        &self.config
    }

    pub fn config_mut(&mut self) -> &mut PeMutatorConfig {
        &mut self.config
    }

    pub fn max_size(&self) -> Option<usize> {
        self.max_size
    }

    pub fn set_max_size(&mut self, max_size: Option<usize>) {
        self.max_size = max_size;
    }
}

impl Default for PeMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl Named for PeMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("PeMutator")
    }
}

impl<S> Mutator<BytesInput, S> for PeMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        let mut pe_input = match PeInput::parse(input.target_bytes().as_ref()) {
            Ok(pe_input) => pe_input,
            Err(_) => {
                if let Some(path) = self.reporting_path() {
                    write_mutation_report(path, &PeMutationReport::default())?;
                }
                return Ok(MutationResult::Skipped);
            }
        };

        let mut core_mutator = CorePeMutator::with_config(
            crate::rng_wrapper::LibAFLRng::new(state.rand_mut()),
            self.config.clone(),
        );

        match core_mutator.mutate_parsed(&mut pe_input) {
            Ok(report) => {
                if let Some(path) = self.reporting_path() {
                    write_mutation_report(path, &report)?;
                }
                let result = if report.any_mutated() {
                    let config = PeSerializationConfig {
                        size_limits: PeSizeLimits {
                            max_materialized_size: self.max_size,
                            max_serialized_size: self.max_size,
                        },
                    };
                    let bytes = match pe_input.to_bytes_with_config(config) {
                        Ok(bytes) => bytes,
                        Err(err)
                            if matches!(
                                err.kind(),
                                CoreErrorKind::Layout | CoreErrorKind::InvalidInput
                            ) =>
                        {
                            return Ok(MutationResult::Skipped);
                        }
                        Err(err) => return Err(core_to_libafl_error(err)),
                    };
                    *input = BytesInput::new(bytes);
                    MutationResult::Mutated
                } else {
                    MutationResult::Skipped
                };
                Ok(result)
            }
            Err(err)
                if matches!(
                    err.kind(),
                    CoreErrorKind::InvalidInput
                        | CoreErrorKind::Parse
                        | CoreErrorKind::Layout
                        | CoreErrorKind::Assembly
                        | CoreErrorKind::Encoding
                ) =>
            {
                if let Some(path) = self.reporting_path() {
                    write_mutation_report(path, &PeMutationReport::default())?;
                }
                Ok(MutationResult::Skipped)
            }
            Err(err) => Err(core_to_libafl_error(err)),
        }
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

pub struct BytesToPeMutator<M> {
    inner: M,
    max_size: Option<usize>,
}

impl<M> BytesToPeMutator<M> {
    pub fn new(inner: M) -> Self {
        Self {
            inner,
            max_size: None,
        }
    }

    pub fn with_max_size(inner: M, max_size: usize) -> Self {
        Self {
            inner,
            max_size: Some(max_size),
        }
    }

    pub fn inner(&self) -> &M {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut M {
        &mut self.inner
    }
}

pub struct CategoryFilteredMutator<M> {
    inner: M,
    required_category: PeMutationCategory,
    enabled_categories: PeMutationCategorySet,
}

impl<M> CategoryFilteredMutator<M> {
    pub fn new(
        inner: M,
        required_category: PeMutationCategory,
        enabled_categories: PeMutationCategorySet,
    ) -> Self {
        Self {
            inner,
            required_category,
            enabled_categories,
        }
    }
}

impl<M, S> Mutator<BytesInput, S> for BytesToPeMutator<M>
where
    M: Mutator<PeInput, S>,
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        let mut pe_input = match PeInput::parse(input.target_bytes().as_ref()) {
            Ok(pe_input) => pe_input,
            Err(_) => return Ok(MutationResult::Skipped),
        };

        let result = self.inner.mutate(state, &mut pe_input)?;
        if matches!(result, MutationResult::Mutated) {
            let config = PeSerializationConfig {
                size_limits: PeSizeLimits {
                    max_materialized_size: self.max_size,
                    max_serialized_size: self.max_size,
                },
            };
            let serialized = match pe_input.to_bytes_with_config(config) {
                Ok(bytes) => bytes,
                Err(err)
                    if matches!(
                        err.kind(),
                        CoreErrorKind::Layout | CoreErrorKind::InvalidInput
                    ) =>
                {
                    return Ok(MutationResult::Skipped);
                }
                Err(err) => return Err(core_to_libafl_error(err)),
            };
            *input = BytesInput::new(serialized);
        }
        Ok(result)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl<I, S, M> Mutator<I, S> for CategoryFilteredMutator<M>
where
    M: Mutator<I, S>,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        if !self.enabled_categories.contains(self.required_category) {
            return Ok(MutationResult::Skipped);
        }
        self.inner.mutate(state, input)
    }

    fn post_exec(&mut self, state: &mut S, new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        self.inner.post_exec(state, new_corpus_id)
    }
}

impl<M> ComposedByMutations for BytesToPeMutator<M>
where
    M: ComposedByMutations,
{
    type Mutations = M::Mutations;

    fn mutations(&self) -> &Self::Mutations {
        self.inner.mutations()
    }

    fn mutations_mut(&mut self) -> &mut Self::Mutations {
        self.inner.mutations_mut()
    }
}

impl<M> ComposedByMutations for CategoryFilteredMutator<M>
where
    M: ComposedByMutations,
{
    type Mutations = M::Mutations;

    fn mutations(&self) -> &Self::Mutations {
        self.inner.mutations()
    }

    fn mutations_mut(&mut self) -> &mut Self::Mutations {
        self.inner.mutations_mut()
    }
}

impl<M> Named for BytesToPeMutator<M>
where
    M: Named,
{
    fn name(&self) -> &Cow<'static, str> {
        self.inner.name()
    }
}

impl<M> Named for CategoryFilteredMutator<M>
where
    M: Named,
{
    fn name(&self) -> &Cow<'static, str> {
        self.inner.name()
    }
}

pub struct GuardedMutationStack<M> {
    inner: M,
}

impl<M> GuardedMutationStack<M> {
    fn new(inner: M) -> Self {
        Self { inner }
    }
}

impl<M> ComposedByMutations for GuardedMutationStack<M>
where
    M: ComposedByMutations,
{
    type Mutations = M::Mutations;

    fn mutations(&self) -> &Self::Mutations {
        self.inner.mutations()
    }

    fn mutations_mut(&mut self) -> &mut Self::Mutations {
        self.inner.mutations_mut()
    }
}

impl<M> Named for GuardedMutationStack<M>
where
    M: Named,
{
    fn name(&self) -> &Cow<'static, str> {
        self.inner.name()
    }
}

impl<I, S, M> Mutator<I, S> for GuardedMutationStack<M>
where
    M: Mutator<I, S>,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        reset_iteration_mutation_guards();
        self.inner.mutate(state, input)
    }

    fn post_exec(&mut self, state: &mut S, new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        self.inner.post_exec(state, new_corpus_id)
    }
}

pub type DefaultPeHavocMutator = GuardedMutationStack<
    HavocScheduledMutator<
        tuple_list_type!(
            CategoryFilteredMutator<BytesToPeMutator<ArchitectureMutator>>,
            CategoryFilteredMutator<BytesToPeMutator<SectionCountMutator>>,
            CategoryFilteredMutator<BytesToPeMutator<SectionHeaderMutator>>,
            CategoryFilteredMutator<BytesToPeMutator<SectionBodyMutator>>,
            CategoryFilteredMutator<BytesToPeMutator<EntryPointMutator>>,
            CategoryFilteredMutator<BytesToPeMutator<ExecutableChunkAssemblyMutator>>,
            CategoryFilteredMutator<BytesToPeMutator<OverlayMutator>>,
            CategoryFilteredMutator<BytesToPeMutator<DataDirectoryEntryMutator>>,
            CategoryFilteredMutator<BytesToPeMutator<ExportDirectoryMutator>>,
            CategoryFilteredMutator<BytesToPeMutator<ResourceDirectoryMutator>>,
        ),
    >,
>;

pub fn default_pe_havoc_mutator() -> DefaultPeHavocMutator {
    default_pe_havoc_mutator_with_categories_and_max_size(PeMutationCategorySet::ALL, None)
}

pub fn default_pe_havoc_mutator_with_categories(
    enabled_categories: PeMutationCategorySet,
) -> DefaultPeHavocMutator {
    default_pe_havoc_mutator_with_categories_and_max_size(enabled_categories, None)
}

pub fn default_pe_havoc_mutator_with_max_size(
    max_serialized_size: Option<usize>,
) -> DefaultPeHavocMutator {
    default_pe_havoc_mutator_with_categories_and_max_size(
        PeMutationCategorySet::ALL,
        max_serialized_size,
    )
}

pub fn default_pe_havoc_mutator_with_categories_and_max_size(
    enabled_categories: PeMutationCategorySet,
    max_serialized_size: Option<usize>,
) -> DefaultPeHavocMutator {
    GuardedMutationStack::new(HavocScheduledMutator::new(tuple_list!(
        bytes_to_pe_category_mutator(
            ArchitectureMutator::with_max_materialized_size(max_serialized_size),
            max_serialized_size,
            PeMutationCategory::Architecture,
            enabled_categories,
        ),
        bytes_to_pe_category_mutator(
            SectionCountMutator::with_max_materialized_size(max_serialized_size),
            max_serialized_size,
            PeMutationCategory::Sections,
            enabled_categories,
        ),
        bytes_to_pe_category_mutator(
            SectionHeaderMutator,
            max_serialized_size,
            PeMutationCategory::Headers,
            enabled_categories,
        ),
        bytes_to_pe_category_mutator(
            SectionBodyMutator::with_max_materialized_size(max_serialized_size),
            max_serialized_size,
            PeMutationCategory::Sections,
            enabled_categories,
        ),
        bytes_to_pe_category_mutator(
            EntryPointMutator::with_max_materialized_size(max_serialized_size),
            max_serialized_size,
            PeMutationCategory::Assembly,
            enabled_categories,
        ),
        bytes_to_pe_category_mutator(
            ExecutableChunkAssemblyMutator::with_max_materialized_size(max_serialized_size),
            max_serialized_size,
            PeMutationCategory::Assembly,
            enabled_categories,
        ),
        bytes_to_pe_category_mutator(
            OverlayMutator::with_limits(DEFAULT_OVERLAY_MAX_LEN, max_serialized_size),
            max_serialized_size,
            PeMutationCategory::Overlay,
            enabled_categories,
        ),
        bytes_to_pe_category_mutator(
            DataDirectoryEntryMutator,
            max_serialized_size,
            PeMutationCategory::DataDirectories,
            enabled_categories,
        ),
        bytes_to_pe_category_mutator(
            ExportDirectoryMutator,
            max_serialized_size,
            PeMutationCategory::DataDirectories,
            enabled_categories,
        ),
        bytes_to_pe_category_mutator(
            ResourceDirectoryMutator,
            max_serialized_size,
            PeMutationCategory::DataDirectories,
            enabled_categories,
        ),
    )))
}

fn bytes_to_pe_mutator<M>(inner: M, max_serialized_size: Option<usize>) -> BytesToPeMutator<M> {
    match max_serialized_size {
        Some(limit) => BytesToPeMutator::with_max_size(inner, limit),
        None => BytesToPeMutator::new(inner),
    }
}

fn bytes_to_pe_category_mutator<M>(
    inner: M,
    max_serialized_size: Option<usize>,
    required_category: PeMutationCategory,
    enabled_categories: PeMutationCategorySet,
) -> CategoryFilteredMutator<BytesToPeMutator<M>> {
    CategoryFilteredMutator::new(
        bytes_to_pe_mutator(inner, max_serialized_size),
        required_category,
        enabled_categories,
    )
}

pub enum PeHavocMutator {
    Default(DefaultPeHavocMutator),
}

impl PeHavocMutator {
    pub fn new() -> Self {
        Self::new_with_categories_and_max_size(PeMutationCategorySet::ALL, None)
    }

    pub fn new_with_categories(enabled_categories: PeMutationCategorySet) -> Self {
        Self::new_with_categories_and_max_size(enabled_categories, None)
    }

    pub fn new_with_max_size(max_serialized_size: Option<usize>) -> Self {
        Self::new_with_categories_and_max_size(PeMutationCategorySet::ALL, max_serialized_size)
    }

    pub fn new_with_categories_and_max_size(
        enabled_categories: PeMutationCategorySet,
        max_serialized_size: Option<usize>,
    ) -> Self {
        Self::Default(default_pe_havoc_mutator_with_categories_and_max_size(
            enabled_categories,
            max_serialized_size,
        ))
    }

    pub fn default_with_max_size(max_serialized_size: Option<usize>) -> Self {
        Self::default_with_categories_and_max_size(PeMutationCategorySet::ALL, max_serialized_size)
    }

    pub fn default_with_categories(enabled_categories: PeMutationCategorySet) -> Self {
        Self::default_with_categories_and_max_size(enabled_categories, None)
    }

    pub fn default_with_categories_and_max_size(
        enabled_categories: PeMutationCategorySet,
        max_serialized_size: Option<usize>,
    ) -> Self {
        Self::Default(default_pe_havoc_mutator_with_categories_and_max_size(
            enabled_categories,
            max_serialized_size,
        ))
    }
}

impl Default for PeHavocMutator {
    fn default() -> Self {
        Self::Default(default_pe_havoc_mutator())
    }
}

impl Named for PeHavocMutator {
    fn name(&self) -> &Cow<'static, str> {
        match self {
            Self::Default(m) => m.name(),
        }
    }
}

impl<S> Mutator<BytesInput, S> for PeHavocMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        match self {
            Self::Default(m) => m.mutate(state, input),
        }
    }

    fn post_exec(&mut self, state: &mut S, new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        match self {
            Self::Default(m) => m.post_exec(state, new_corpus_id),
        }
    }
}
