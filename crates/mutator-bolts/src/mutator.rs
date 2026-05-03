use crate::rng::MutRng;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StackDepthConfig {
    pub min_stack_depth: usize,
    pub max_stack_depth: usize,
}

impl StackDepthConfig {
    pub fn normalized_stack_depth_bounds(&self) -> (usize, usize) {
        let min = self.min_stack_depth.max(1);
        let max = self.max_stack_depth.max(min);
        (min, max)
    }

    pub fn stack_depth<R: MutRng>(&self, rng: &mut R) -> usize {
        let (min, max) = self.normalized_stack_depth_bounds();
        min + rng.below(max - min + 1)
    }
}

impl Default for StackDepthConfig {
    fn default() -> Self {
        Self {
            min_stack_depth: 1,
            max_stack_depth: 8,
        }
    }
}

pub trait MutationRegistry<Kind> {
    fn mutations(&self) -> &[Kind];
}

#[derive(Debug, Clone)]
pub struct MutationReport<Kind> {
    pub requested_stack_depth: usize,
    pub selected_mutations: Vec<Kind>,
    pub mutated_count: usize,
    pub skipped_count: usize,
}

impl<Kind> Default for MutationReport<Kind> {
    fn default() -> Self {
        Self {
            requested_stack_depth: 0,
            selected_mutations: Vec::new(),
            mutated_count: 0,
            skipped_count: 0,
        }
    }
}

impl<Kind> MutationReport<Kind> {
    pub fn attempted_count(&self) -> usize {
        self.selected_mutations.len()
    }

    pub fn any_mutated(&self) -> bool {
        self.mutated_count != 0
    }
}
