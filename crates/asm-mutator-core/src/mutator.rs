use crate::assembly::AssemblyArch;

pub struct AssemblyMutator {
    pub arch: AssemblyArch,
}

impl AssemblyMutator {
    pub fn new(arch: AssemblyArch) -> Self {
        Self { arch }
    }
}