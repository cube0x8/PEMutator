use crate::error::Error;
use crate::ir::{BranchTarget, PlacementContext};
use crate::rng::MutRng;

pub fn random_short_branch_target<R: MutRng>(rand: &mut R) -> BranchTarget {
    match rand.below(3) {
        0 => BranchTarget::IntraBlockForward,
        1 => BranchTarget::IntraBlockBackward,
        _ => BranchTarget::RandomInBlock,
    }
}

pub fn random_branch_target<R: MutRng>(rand: &mut R) -> BranchTarget {
    match rand.below(4) {
        0 => BranchTarget::IntraBlockForward,
        1 => BranchTarget::IntraBlockBackward,
        2 => BranchTarget::RandomInBlock,
        _ => BranchTarget::RandomInSection,
    }
}

pub fn resolve_branch_target_va<R: MutRng>(
    rand: &mut R,
    target: BranchTarget,
    branch_index: usize,
    insn_offsets: &[u64],
    placement_context: &PlacementContext,
    block_end_va: u64,
    next_ip: u64,
    min_displacement: i64,
    max_displacement: i64,
) -> Result<u64, Error> {
    let target_offset = match target {
        BranchTarget::IntraBlockForward => insn_offsets
            .get(branch_index + 1)
            .copied()
            .unwrap_or_else(|| *insn_offsets.last().unwrap_or(&0)),
        BranchTarget::IntraBlockBackward => {
            if branch_index == 0 {
                *insn_offsets.first().unwrap_or(&0)
            } else {
                insn_offsets[rand.below(branch_index)]
            }
        }
        BranchTarget::RandomInBlock => {
            if insn_offsets.is_empty() {
                0
            } else {
                insn_offsets[rand.below(insn_offsets.len())]
            }
        }
        BranchTarget::RandomInSection => {
            let section_start = placement_context.section_start_va;
            let section_end = placement_context.section_end_va;
            if section_end <= section_start {
                return Err(Error::illegal_argument(
                    "invalid section bounds for branch resolution",
                ));
            }

            let reachable_start = if min_displacement < 0 {
                next_ip.saturating_sub(min_displacement.unsigned_abs())
            } else {
                next_ip.saturating_add(min_displacement as u64)
            };
            let reachable_end_exclusive = next_ip
                .checked_add(max_displacement as u64)
                .and_then(|end| end.checked_add(1))
                .unwrap_or(u64::MAX);

            let window_start = section_start.max(reachable_start);
            let window_end = section_end.min(reachable_end_exclusive);
            if window_end <= window_start {
                return Err(Error::illegal_argument(
                    "cannot resolve section-random branch inside reachable displacement window",
                ));
            }

            let window_len = window_end
                .checked_sub(window_start)
                .ok_or_else(|| Error::illegal_argument("reachable branch window underflowed"))?;
            let window_len = usize::try_from(window_len).map_err(|_| {
                Error::illegal_argument("reachable branch window exceeds host usize")
            })?;
            return Ok(window_start + rand.below(window_len) as u64);
        }
        BranchTarget::AbsoluteVa(va) => return Ok(va),
    };

    let target_va = placement_context.block_base_va + target_offset;
    if target_va > block_end_va {
        return Err(Error::illegal_argument(format!(
            "branch target offset resolved beyond block end: 0x{target_va:x} > 0x{block_end_va:x}"
        )));
    }
    Ok(target_va)
}

pub fn ensure_branch_target_in_section(
    target_va: u64,
    placement_context: &PlacementContext,
) -> Result<(), Error> {
    if target_va < placement_context.section_start_va
        || target_va >= placement_context.section_end_va
    {
        return Err(Error::illegal_argument(format!(
            "branch target 0x{target_va:x} is outside section bounds [0x{:x}, 0x{:x})",
            placement_context.section_start_va, placement_context.section_end_va
        )));
    }
    Ok(())
}
