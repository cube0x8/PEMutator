pub const DEFAULT_SEED: u64 = 0x9e37_79b9_7f4a_7c15;

pub trait MutRng {
    fn next_u64(&mut self) -> u64;

    fn below(&mut self, upper_bound: usize) -> usize {
        if upper_bound == 0 {
            0
        } else {
            (self.next_u64() as usize) % upper_bound
        }
    }

    fn coinflip(&mut self, p: f64) -> bool {
        let threshold = (p * (u64::MAX as f64)) as u64;
        self.next_u64() < threshold
    }

    fn next_u8(&mut self) -> u8 {
        (self.next_u64() & 0xFF) as u8
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { DEFAULT_SEED } else { seed },
        }
    }
}

impl MutRng for SimpleRng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
}
