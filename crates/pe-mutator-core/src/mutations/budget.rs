use crate::error::Error;
use crate::pe::{PeInput, PeSizeLimits};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeSizeBudget {
    limits: PeSizeLimits,
    current_materialized_size: usize,
}

impl PeSizeBudget {
    pub fn from_input(input: &PeInput, limits: PeSizeLimits) -> Result<Self, Error> {
        let current_materialized_size = input.materialized_size();
        if let Some(max_materialized_size) = limits.max_materialized_size {
            if current_materialized_size > max_materialized_size {
                return Err(Error::layout(format!(
                    "materialized PE size {current_materialized_size} exceeds configured maximum size {max_materialized_size}"
                )));
            }
        }

        Ok(Self {
            limits,
            current_materialized_size,
        })
    }

    pub fn limits(&self) -> PeSizeLimits {
        self.limits
    }

    pub fn current_materialized_size(&self) -> usize {
        self.current_materialized_size
    }

    pub fn remaining_materialized_budget(&self) -> Option<usize> {
        self.limits
            .max_materialized_size
            .map(|max| max.saturating_sub(self.current_materialized_size))
    }

    pub fn try_grow_by(&mut self, delta: usize) -> Result<(), Error> {
        let new_size = self
            .current_materialized_size
            .checked_add(delta)
            .ok_or_else(|| Error::layout("materialized PE size overflowed"))?;
        if let Some(max_materialized_size) = self.limits.max_materialized_size {
            if new_size > max_materialized_size {
                return Err(Error::layout(format!(
                    "materialized PE size {new_size} exceeds configured maximum size {max_materialized_size}"
                )));
            }
        }

        self.current_materialized_size = new_size;
        Ok(())
    }

    pub fn shrink_by(&mut self, delta: usize) {
        self.current_materialized_size = self.current_materialized_size.saturating_sub(delta);
    }

    pub fn try_resize_delta(&mut self, old_len: usize, new_len: usize) -> Result<(), Error> {
        match new_len.cmp(&old_len) {
            std::cmp::Ordering::Greater => self.try_grow_by(new_len - old_len),
            std::cmp::Ordering::Less => {
                self.shrink_by(old_len - new_len);
                Ok(())
            }
            std::cmp::Ordering::Equal => Ok(()),
        }
    }
}
