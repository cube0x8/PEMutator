use libafl_bolts::rands::Rand;
use pe_mutator_core::core::rng::MutRng;

pub struct LibAFLRng<'a, R> {
    inner: &'a mut R,
}

impl<'a, R> LibAFLRng<'a, R> {
    pub fn new(inner: &'a mut R) -> Self {
        Self { inner }
    }
}

impl<R: Rand> MutRng for LibAFLRng<'_, R> {
    fn next_u64(&mut self) -> u64 {
        self.inner.next()
    }
}
