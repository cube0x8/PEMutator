mod eat;
mod fields;
mod names;
mod ordinal;
use crate::core::rng::MutRng;
use crate::mutations::shared::RawMutationResult;
use crate::pe::PeInput;
use crate::pe::data_directories::ExportDirectory;

pub struct ExportDirectoryMutations;

const TABLE_CONTENT_WEIGHT: usize = 60;
const COUNT_AND_RELATIONS_WEIGHT: usize = 25;
const RVA_LOCATOR_FIELDS_WEIGHT: usize = 10;
const VERSION_TIMESTAMP_FLAGS_WEIGHT: usize = 5;

impl ExportDirectoryMutations {
    pub fn random_mutation<R: MutRng>(input: &mut PeInput, rng: &mut R) -> RawMutationResult {
        input.export_directory =
            ExportDirectory::load_for_mutation(&input.data_directories, &input.sections);
        if input.export_directory.is_none() {
            return RawMutationResult::Skipped;
        }

        dispatch_export_mutation(input, rng)
    }
}

fn dispatch_export_mutation<R: MutRng>(input: &mut PeInput, rng: &mut R) -> RawMutationResult {
    let bucket = rng.below(
        TABLE_CONTENT_WEIGHT
            + COUNT_AND_RELATIONS_WEIGHT
            + RVA_LOCATOR_FIELDS_WEIGHT
            + VERSION_TIMESTAMP_FLAGS_WEIGHT,
    );

    if bucket < TABLE_CONTENT_WEIGHT {
        return mutate_table_content(input, rng);
    }
    if bucket < TABLE_CONTENT_WEIGHT + COUNT_AND_RELATIONS_WEIGHT {
        return fields::mutate_count_and_relations(input, rng);
    }
    if bucket < TABLE_CONTENT_WEIGHT + COUNT_AND_RELATIONS_WEIGHT + RVA_LOCATOR_FIELDS_WEIGHT {
        return fields::mutate_rva_locator_fields(input, rng);
    }

    fields::mutate_version_timestamp_and_flags(input, rng)
}

// Dispatches mutations that operate on export table contents.
fn mutate_table_content<R: MutRng>(input: &mut PeInput, rng: &mut R) -> RawMutationResult {
    let start = rng.below(3);
    for offset in 0..3 {
        let mutated = match (start + offset) % 3 {
            0 => ordinal::random_mutation(input, rng),
            1 => eat::random_mutation(input, rng),
            _ => names::random_mutation(input, rng),
        };
        if mutated {
            return RawMutationResult::Mutated;
        }
    }

    RawMutationResult::Skipped
}

#[cfg(test)]
mod tests {
    use super::ExportDirectoryMutations;
    use crate::core::SimpleRng;
    use crate::mutations::shared::RawMutationResult;
    use crate::pe::PeInput;

    #[test]
    fn random_mutation_skips_when_export_directory_is_missing() {
        let mut input = PeInput::template(crate::pe::IMAGE_FILE_MACHINE_AMD64);
        let mut rng = SimpleRng::new(17);

        let result = ExportDirectoryMutations::random_mutation(&mut input, &mut rng);

        assert_eq!(result, RawMutationResult::Skipped);
        assert!(input.export_directory.is_none());
        assert!(
            input
                .data_directories
                .first()
                .is_none_or(|directory| directory.virtual_address == 0)
        );
    }
}
