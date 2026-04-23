mod resource;

use crate::core::rng::MutRng;
use crate::mutations::mutations::InPlaceMutation;
use crate::mutations::shared::RawMutationResult;
use crate::pe::data_directories::parse_resource_directory_tree;
use crate::pe::PeInput;

pub struct ResourceDirectoryMutations;

impl ResourceDirectoryMutations {
    pub fn random_mutation<R: MutRng>(input: &mut PeInput, rng: &mut R) -> RawMutationResult {
        input.resource_directory =
            parse_resource_directory_tree(&input.data_directories, &input.sections);

        resource::random_mutation(input, rng)
    }
}

impl InPlaceMutation for ResourceDirectoryMutations {
    fn random_mutation<R: MutRng>(input: &mut PeInput, rng: &mut R) -> RawMutationResult {
        Self::random_mutation(input, rng)
    }
}
