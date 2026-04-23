mod entry_point;
mod executable_chunk;

pub use entry_point::EntryPointMutations;
pub use executable_chunk::{
    ExecutableChunkAssemblyMutations, plan_executable_chunk_assembly_mutation,
};
