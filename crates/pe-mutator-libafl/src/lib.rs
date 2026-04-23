pub use pe_mutator_core::{arch, assembly, core, encoder, error, ir, pe, utils};
pub mod mutator;
pub mod pe_mutator;
pub mod rng_wrapper;

pub mod mutators {
    pub use super::mutator::*;
}

pub use mutator::*;
pub use pe_mutator::*;
pub use rng_wrapper::LibAFLRng;

#[cfg(test)]
mod tests {
    use crate::{
        default_pe_havoc_mutator_with_categories_and_max_size, ArchitectureMutator,
        DataDirectoryEntryMutator, EntryPointMutator, ExecutableChunkAssemblyMutator,
        ExportDirectoryMutator, OverlayMutator, ResourceDirectoryMutator, SectionBodyMutator,
        SectionCountMutator, SectionHeaderMutator, DEFAULT_OVERLAY_MAX_LEN,
    };
    use pe_mutator_core::core::{PeMutationCategorySet, PeMutationKind};

    #[test]
    fn root_exports_cover_every_libafl_mutator_wrapper() {
        let _ = ArchitectureMutator::new();
        let _ = SectionCountMutator::new();
        let _ = SectionHeaderMutator;
        let _ = SectionBodyMutator::new();
        let _ = EntryPointMutator::new();
        let _ = ExecutableChunkAssemblyMutator::new();
        let _ = OverlayMutator::new(DEFAULT_OVERLAY_MAX_LEN);
        let _ = DataDirectoryEntryMutator;
        let _ = ExportDirectoryMutator;
        let _ = ResourceDirectoryMutator;
    }

    #[test]
    fn default_havoc_mutator_still_tracks_all_core_mutation_kinds() {
        let _ =
            default_pe_havoc_mutator_with_categories_and_max_size(PeMutationCategorySet::ALL, None);
        assert_eq!(PeMutationKind::ALL.len(), 10);
    }
}
