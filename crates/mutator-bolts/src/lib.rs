pub mod error;
pub mod io;
pub mod mutator;
pub mod rng;

pub use error::{Error, ErrorKind, Result};
pub use io::*;
pub use mutator::{MutationRegistry, MutationReport, StackDepthConfig};
pub use rng::{DEFAULT_SEED, MutRng, SimpleRng};
