use crate::{
    ArchitectureMutations, DataDirectoryEntryMutations, EntryPointMutations,
    ExecutableChunkAssemblyMutations, MutRng, OverlayMutations, RawMutationResult,
    ResourceDirectoryMutations, SectionBodyMutations, SectionCountMutations,
    SectionHeaderMutations,
    error::{Error, ErrorKind},
    mutations::ExportDirectoryMutations,
    pe::PeInput,
};
use mutator_bolts::{MutationRegistry, MutationReport, StackDepthConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PeMutationKind {
    Architecture = 0,
    SectionCount = 1,
    SectionHeader = 2,
    SectionBody = 3,
    EntryPoint = 4,
    ExecutableChunkAssembly = 5,
    Overlay = 6,
    DataDirectoryEntry = 7,
    ExportDirectory = 8,
    ResourceDirectory = 9,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PeMutationCategory {
    Architecture = 0,
    Headers = 1,
    Sections = 2,
    Assembly = 3,
    DataDirectories = 4,
    Overlay = 5,
}

impl PeMutationCategory {
    pub const ALL: [Self; 6] = [
        Self::Architecture,
        Self::Headers,
        Self::Sections,
        Self::Assembly,
        Self::DataDirectories,
        Self::Overlay,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Architecture => "Architecture",
            Self::Headers => "Headers",
            Self::Sections => "Sections",
            Self::Assembly => "Assembly",
            Self::DataDirectories => "DataDirectories",
            Self::Overlay => "Overlay",
        }
    }
}

impl PeMutationKind {
    fn recover_mutation_error(err: Error) -> Result<RawMutationResult, Error> {
        match err.kind() {
            ErrorKind::InvalidInput
            | ErrorKind::Parse
            | ErrorKind::Layout
            | ErrorKind::Assembly
            | ErrorKind::Encoding => Ok(RawMutationResult::Skipped),
            ErrorKind::Internal => Err(err),
        }
    }

    pub const ALL: [Self; 10] = [
        Self::Architecture,
        Self::SectionCount,
        Self::SectionHeader,
        Self::SectionBody,
        Self::EntryPoint,
        Self::ExecutableChunkAssembly,
        Self::Overlay,
        Self::DataDirectoryEntry,
        Self::ExportDirectory,
        Self::ResourceDirectory,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Architecture => "Architecture",
            Self::SectionCount => "SectionCount",
            Self::SectionHeader => "SectionHeader",
            Self::SectionBody => "SectionBody",
            Self::EntryPoint => "EntryPoint",
            Self::ExecutableChunkAssembly => "ExecutableChunkAssembly",
            Self::Overlay => "Overlay",
            Self::DataDirectoryEntry => "DataDirectoryEntry",
            Self::ExportDirectory => "ExportDirectory",
            Self::ResourceDirectory => "ResourceDirectory",
        }
    }

    pub const fn category(self) -> PeMutationCategory {
        match self {
            Self::Architecture => PeMutationCategory::Architecture,
            Self::SectionHeader => PeMutationCategory::Headers,
            Self::SectionCount | Self::SectionBody => PeMutationCategory::Sections,
            Self::EntryPoint | Self::ExecutableChunkAssembly => PeMutationCategory::Assembly,
            Self::Overlay => PeMutationCategory::Overlay,
            Self::DataDirectoryEntry | Self::ExportDirectory | Self::ResourceDirectory => {
                PeMutationCategory::DataDirectories
            }
        }
    }

    pub fn apply<R: MutRng>(
        self,
        input: &mut PeInput,
        rng: &mut R,
        config: &PeMutatorConfig,
    ) -> Result<RawMutationResult, Error> {
        let result = match self {
            Self::Architecture => ArchitectureMutations::random_mutation(input, rng),
            Self::SectionCount => SectionCountMutations::random_mutation(input, rng),
            Self::SectionHeader => Ok(SectionHeaderMutations::random_mutation(input, rng)),
            Self::SectionBody => Ok(SectionBodyMutations::default().random_mutation(input, rng)),
            Self::EntryPoint => EntryPointMutations::random_mutation(input, rng),
            Self::ExecutableChunkAssembly => {
                ExecutableChunkAssemblyMutations::random_mutation(input, rng)
            }
            Self::Overlay => Ok(OverlayMutations::random_mutation(
                input,
                rng,
                config.overlay_max_len,
            )),
            Self::DataDirectoryEntry => {
                Ok(DataDirectoryEntryMutations::random_mutation(input, rng))
            }
            Self::ExportDirectory => Ok(ExportDirectoryMutations::random_mutation(input, rng)),
            Self::ResourceDirectory => Ok(ResourceDirectoryMutations::random_mutation(input, rng)),
        };
        result.or_else(Self::recover_mutation_error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct PeMutationSet {
    bits: u64,
}

impl PeMutationSet {
    const fn bit(kind: PeMutationKind) -> u64 {
        1_u64 << (kind as u8)
    }

    pub const NONE: Self = Self { bits: 0 };
    pub const DEFAULT: Self = Self {
        bits: Self::bit(PeMutationKind::Architecture)
            | Self::bit(PeMutationKind::SectionCount)
            | Self::bit(PeMutationKind::SectionHeader)
            | Self::bit(PeMutationKind::SectionBody)
            | Self::bit(PeMutationKind::EntryPoint)
            | Self::bit(PeMutationKind::ExecutableChunkAssembly)
            | Self::bit(PeMutationKind::Overlay),
    };
    pub const ALL: Self = Self {
        bits: Self::bit(PeMutationKind::Architecture)
            | Self::bit(PeMutationKind::SectionCount)
            | Self::bit(PeMutationKind::SectionHeader)
            | Self::bit(PeMutationKind::SectionBody)
            | Self::bit(PeMutationKind::EntryPoint)
            | Self::bit(PeMutationKind::ExecutableChunkAssembly)
            | Self::bit(PeMutationKind::Overlay)
            | Self::bit(PeMutationKind::DataDirectoryEntry)
            | Self::bit(PeMutationKind::ExportDirectory)
            | Self::bit(PeMutationKind::ResourceDirectory),
    };

    pub const fn from_bits(bits: u64) -> Self {
        Self {
            bits: bits & Self::ALL.bits,
        }
    }

    pub const fn bits(self) -> u64 {
        self.bits
    }

    pub const fn contains(self, kind: PeMutationKind) -> bool {
        (self.bits & Self::bit(kind)) != 0
    }

    pub fn insert(&mut self, kind: PeMutationKind) {
        self.bits |= Self::bit(kind);
    }

    pub fn remove(&mut self, kind: PeMutationKind) {
        self.bits &= !Self::bit(kind);
    }

    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }
}

impl Default for PeMutationSet {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct PeMutationCategorySet {
    bits: u64,
}

impl PeMutationCategorySet {
    const fn bit(category: PeMutationCategory) -> u64 {
        1_u64 << (category as u8)
    }

    pub const NONE: Self = Self { bits: 0 };
    pub const DEFAULT: Self = Self::ALL;
    pub const ALL: Self = Self {
        bits: Self::bit(PeMutationCategory::Architecture)
            | Self::bit(PeMutationCategory::Headers)
            | Self::bit(PeMutationCategory::Sections)
            | Self::bit(PeMutationCategory::Assembly)
            | Self::bit(PeMutationCategory::DataDirectories)
            | Self::bit(PeMutationCategory::Overlay),
    };

    pub const fn from_bits(bits: u64) -> Self {
        Self {
            bits: bits & Self::ALL.bits,
        }
    }

    pub const fn bits(self) -> u64 {
        self.bits
    }

    pub const fn contains(self, category: PeMutationCategory) -> bool {
        (self.bits & Self::bit(category)) != 0
    }

    pub fn insert(&mut self, category: PeMutationCategory) {
        self.bits |= Self::bit(category);
    }

    pub fn remove(&mut self, category: PeMutationCategory) {
        self.bits &= !Self::bit(category);
    }

    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }
}

impl Default for PeMutationCategorySet {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeMutatorConfig {
    pub stack: StackDepthConfig,
    pub overlay_max_len: usize,
    pub enabled_categories: PeMutationCategorySet,
    pub enabled_mutations: PeMutationSet,
}

impl PeMutatorConfig {
    pub fn normalized_stack_depth_bounds(&self) -> (usize, usize) {
        self.stack.normalized_stack_depth_bounds()
    }

    pub fn stack_depth<R: MutRng>(&self, rng: &mut R) -> usize {
        self.stack.stack_depth(rng)
    }

    pub fn is_mutation_enabled(&self, kind: PeMutationKind) -> bool {
        self.enabled_categories.contains(kind.category()) && self.enabled_mutations.contains(kind)
    }

    pub fn is_category_enabled(&self, category: PeMutationCategory) -> bool {
        self.enabled_categories.contains(category)
    }
}

impl Default for PeMutatorConfig {
    fn default() -> Self {
        Self {
            stack: StackDepthConfig::default(),
            overlay_max_len: 0x1000,
            enabled_categories: PeMutationCategorySet::DEFAULT,
            enabled_mutations: PeMutationSet::DEFAULT,
        }
    }
}

pub type PeMutationReport = MutationReport<PeMutationKind>;
pub trait PeMutationRegistry: MutationRegistry<PeMutationKind> {}
impl<T> PeMutationRegistry for T where T: MutationRegistry<PeMutationKind> {}

#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultPeMutationRegistry;

impl MutationRegistry<PeMutationKind> for DefaultPeMutationRegistry {
    fn mutations(&self) -> &[PeMutationKind] {
        &PeMutationKind::ALL
    }
}

pub struct PeMutator<R, Registry = DefaultPeMutationRegistry> {
    rng: R,
    config: PeMutatorConfig,
    registry: Registry,
}

impl<R> PeMutator<R, DefaultPeMutationRegistry>
where
    R: MutRng,
{
    pub fn new(rng: R) -> Self {
        Self::with_config(rng, PeMutatorConfig::default())
    }

    pub fn with_config(rng: R, config: PeMutatorConfig) -> Self {
        Self::with_registry(rng, config, DefaultPeMutationRegistry)
    }
}

impl<R, Registry> PeMutator<R, Registry>
where
    R: MutRng,
    Registry: PeMutationRegistry,
{
    pub fn with_registry(rng: R, config: PeMutatorConfig, registry: Registry) -> Self {
        Self {
            rng,
            config,
            registry,
        }
    }

    pub fn rng(&self) -> &R {
        &self.rng
    }

    pub fn rng_mut(&mut self) -> &mut R {
        &mut self.rng
    }

    pub fn config(&self) -> &PeMutatorConfig {
        &self.config
    }

    pub fn config_mut(&mut self) -> &mut PeMutatorConfig {
        &mut self.config
    }

    pub fn collect_enabled_mutations(&self) -> Vec<PeMutationKind> {
        self.registry
            .mutations()
            .iter()
            .copied()
            .filter(|kind| self.config.is_mutation_enabled(*kind))
            .collect()
    }

    pub fn mutate_parsed(&mut self, input: &mut PeInput) -> Result<PeMutationReport, Error> {
        let enabled_mutations = self.collect_enabled_mutations();
        if enabled_mutations.is_empty() {
            return Ok(PeMutationReport::default());
        }

        let requested_stack_depth = self.config.stack_depth(&mut self.rng);
        let mut report = PeMutationReport {
            requested_stack_depth,
            ..PeMutationReport::default()
        };
        let mut export_directory_locked = false;

        for _ in 0..requested_stack_depth {
            let selectable_mutations: Vec<_> = enabled_mutations
                .iter()
                .copied()
                .filter(|kind| {
                    !export_directory_locked
                        || (*kind != PeMutationKind::ExportDirectory
                            && *kind != PeMutationKind::DataDirectoryEntry)
                })
                .collect();
            if selectable_mutations.is_empty() {
                break;
            }

            let mutation = selectable_mutations[self.rng.below(selectable_mutations.len())];
            report.selected_mutations.push(mutation);
            let result = match mutation {
                PeMutationKind::DataDirectoryEntry => {
                    let outcome = DataDirectoryEntryMutations::random_mutation_with_outcome(
                        input,
                        &mut self.rng,
                    );
                    if outcome.result == RawMutationResult::Mutated
                        && outcome.touched_export_directory
                    {
                        export_directory_locked = true;
                    }
                    Ok(outcome.result)
                }
                _ => mutation.apply(input, &mut self.rng, &self.config),
            }?;
            match result {
                RawMutationResult::Mutated => {
                    if mutation == PeMutationKind::ExportDirectory {
                        export_directory_locked = true;
                    }
                    report.mutated_count += 1
                }
                RawMutationResult::Skipped => report.skipped_count += 1,
            }
        }

        Ok(report)
    }

    pub fn mutate_bytes(&mut self, bytes: &[u8]) -> Result<(Vec<u8>, PeMutationReport), Error> {
        let mut input = PeInput::parse(bytes)?;
        let report = self.mutate_parsed(&mut input)?;
        let bytes = input.to_bytes()?;
        Ok((bytes, report))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PeMutationCategory, PeMutationCategorySet, PeMutationKind, PeMutationSet, PeMutatorConfig,
        RawMutationResult,
    };
    use crate::error::Error;

    #[test]
    fn recoverable_mutation_errors_become_skips() {
        let result = PeMutationKind::recover_mutation_error(Error::encoding("iced failed"))
            .expect("encoding errors during mutation should not abort the iteration");
        assert_eq!(result, RawMutationResult::Skipped);
    }

    #[test]
    fn internal_mutation_errors_still_propagate() {
        let err = PeMutationKind::recover_mutation_error(Error::internal("broken invariant"))
            .expect_err("internal errors should still be surfaced");
        assert_eq!(err.message(), "broken invariant");
    }

    #[test]
    fn mutation_kind_reports_its_category() {
        assert_eq!(
            PeMutationKind::ExecutableChunkAssembly.category(),
            PeMutationCategory::Assembly
        );
        assert_eq!(
            PeMutationKind::ExportDirectory.category(),
            PeMutationCategory::DataDirectories
        );
    }

    #[test]
    fn mutator_config_requires_kind_and_category_to_be_enabled() {
        let mut config = PeMutatorConfig::default();
        assert!(config.is_mutation_enabled(PeMutationKind::EntryPoint));

        config.enabled_categories = PeMutationCategorySet::NONE;
        config
            .enabled_categories
            .insert(PeMutationCategory::Assembly);
        assert!(config.is_mutation_enabled(PeMutationKind::EntryPoint));
        assert!(!config.is_mutation_enabled(PeMutationKind::Overlay));

        config.enabled_mutations = PeMutationSet::NONE;
        config.enabled_mutations.insert(PeMutationKind::Overlay);
        assert!(!config.is_mutation_enabled(PeMutationKind::Overlay));
    }
}
