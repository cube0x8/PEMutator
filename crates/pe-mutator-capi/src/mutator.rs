use pe_mutator_core::core::{
    PeMutationCategory, PeMutationCategorySet, PeMutationKind, PeMutationReport, PeMutationSet,
    PeMutator as CorePeMutator, PeMutatorConfig, SimpleRng,
};
use pe_mutator_core::error::Error;
use pe_mutator_core::pe::PeInput;

#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeMutateCategoryBits {
    None = 0,
    Architecture = 1_u64 << (PeMutationCategory::Architecture as u8),
    Headers = 1_u64 << (PeMutationCategory::Headers as u8),
    Sections = 1_u64 << (PeMutationCategory::Sections as u8),
    Assembly = 1_u64 << (PeMutationCategory::Assembly as u8),
    DataDirectories = 1_u64 << (PeMutationCategory::DataDirectories as u8),
    Overlay = 1_u64 << (PeMutationCategory::Overlay as u8),
    All = PeMutationCategorySet::ALL.bits(),
}

#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeMutateMutationBits {
    None = 0,
    Architecture = 1_u64 << (PeMutationKind::Architecture as u8),
    SectionCount = 1_u64 << (PeMutationKind::SectionCount as u8),
    SectionHeader = 1_u64 << (PeMutationKind::SectionHeader as u8),
    SectionBody = 1_u64 << (PeMutationKind::SectionBody as u8),
    EntryPoint = 1_u64 << (PeMutationKind::EntryPoint as u8),
    ExecutableChunkAssembly = 1_u64 << (PeMutationKind::ExecutableChunkAssembly as u8),
    Overlay = 1_u64 << (PeMutationKind::Overlay as u8),
    DataDirectoryEntry = 1_u64 << (PeMutationKind::DataDirectoryEntry as u8),
    ExportDirectory = 1_u64 << (PeMutationKind::ExportDirectory as u8),
    ResourceDirectory = 1_u64 << (PeMutationKind::ResourceDirectory as u8),
    All = PeMutationSet::ALL.bits(),
}

pub const PE_MUTATE_CATEGORY_NONE: u64 = 0;
pub const PE_MUTATE_CATEGORY_ARCHITECTURE: u64 = 1;
pub const PE_MUTATE_CATEGORY_HEADERS: u64 = 1 << 1;
pub const PE_MUTATE_CATEGORY_SECTIONS: u64 = 1 << 2;
pub const PE_MUTATE_CATEGORY_ASSEMBLY: u64 = 1 << 3;
pub const PE_MUTATE_CATEGORY_DATA_DIRECTORIES: u64 = 1 << 4;
pub const PE_MUTATE_CATEGORY_OVERLAY: u64 = 1 << 5;
pub const PE_MUTATE_CATEGORY_ALL: u64 = 0x3f;

pub const PE_MUTATE_MUTATION_NONE: u64 = 0;
pub const PE_MUTATE_MUTATION_ARCHITECTURE: u64 = 1;
pub const PE_MUTATE_MUTATION_SECTION_COUNT: u64 = 1 << 1;
pub const PE_MUTATE_MUTATION_SECTION_HEADER: u64 = 1 << 2;
pub const PE_MUTATE_MUTATION_SECTION_BODY: u64 = 1 << 3;
pub const PE_MUTATE_MUTATION_ENTRY_POINT: u64 = 1 << 4;
pub const PE_MUTATE_MUTATION_EXECUTABLE_CHUNK_ASSEMBLY: u64 = 1 << 5;
pub const PE_MUTATE_MUTATION_OVERLAY: u64 = 1 << 6;
pub const PE_MUTATE_MUTATION_DATA_DIRECTORY_ENTRY: u64 = 1 << 7;
pub const PE_MUTATE_MUTATION_EXPORT_DIRECTORY: u64 = 1 << 8;
pub const PE_MUTATE_MUTATION_RESOURCE_DIRECTORY: u64 = 1 << 9;
pub const PE_MUTATE_MUTATION_ALL: u64 = 0x3ff;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PeMutateCfg {
    pub seed: u64,
    pub min_stack_depth: usize,
    pub max_stack_depth: usize,
    pub overlay_max_len: usize,
    pub enabled_categories: u64,
    pub enabled_mutations: u64,
}

impl Default for PeMutateCfg {
    fn default() -> Self {
        let config = PeMutatorConfig::default();
        Self {
            seed: 0,
            min_stack_depth: config.min_stack_depth,
            max_stack_depth: config.max_stack_depth,
            overlay_max_len: config.overlay_max_len,
            enabled_categories: config.enabled_categories.bits(),
            enabled_mutations: config.enabled_mutations.bits(),
        }
    }
}

impl From<PeMutateCfg> for PeMutatorConfig {
    fn from(value: PeMutateCfg) -> Self {
        Self {
            min_stack_depth: value.min_stack_depth,
            max_stack_depth: value.max_stack_depth,
            overlay_max_len: value.overlay_max_len,
            enabled_categories: PeMutationCategorySet::from_bits(value.enabled_categories),
            enabled_mutations: PeMutationSet::from_bits(value.enabled_mutations),
        }
    }
}

pub struct PEMutator {
    inner: CorePeMutator<SimpleRng>,
}

impl PEMutator {
    pub fn new(seed: u64) -> Self {
        Self::with_config(PeMutateCfg {
            seed,
            ..PeMutateCfg::default()
        })
    }

    pub fn with_config(cfg: PeMutateCfg) -> Self {
        let rng = SimpleRng::new(cfg.seed);
        let config = PeMutatorConfig::from(cfg);
        Self {
            inner: CorePeMutator::with_config(rng, config),
        }
    }

    pub fn mutate_parsed(&mut self, input: &mut PeInput) -> Result<PeMutationReport, Error> {
        self.inner.mutate_parsed(input)
    }

    pub fn mutate_bytes(&mut self, bytes: &[u8]) -> Result<(Vec<u8>, PeMutationReport), Error> {
        self.inner.mutate_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::{PeMutateCategoryBits, PeMutateCfg, PeMutateMutationBits};
    use pe_mutator_core::core::{
        PeMutationCategorySet, PeMutationKind, PeMutationSet, PeMutatorConfig,
    };

    #[test]
    fn capi_category_bits_match_core_category_set() {
        assert_eq!(
            PeMutateCategoryBits::None as u64,
            PeMutationCategorySet::NONE.bits()
        );
        assert_eq!(
            PeMutateCategoryBits::All as u64,
            PeMutationCategorySet::ALL.bits()
        );
    }

    #[test]
    fn capi_mutation_bits_match_core_mutation_set() {
        assert_eq!(
            PeMutateMutationBits::None as u64,
            PeMutationSet::NONE.bits()
        );
        assert_eq!(PeMutateMutationBits::All as u64, PeMutationSet::ALL.bits());

        for kind in PeMutationKind::ALL {
            let cfg = PeMutateCfg {
                enabled_categories: 1_u64 << (kind.category() as u8),
                enabled_mutations: 1_u64 << (kind as u8),
                ..PeMutateCfg::default()
            };
            let config = PeMutatorConfig::from(cfg);
            assert!(config.enabled_categories.contains(kind.category()));
            assert!(config.enabled_mutations.contains(kind));
        }
    }
}
