use std::collections::HashSet;
use std::path::Path;

use crate::core::network::{CanonicalCidr, cidr_overlaps, parse_ip_cidr_non_strict};
use crate::error::KidoboError;

use super::storage::{BlocklistFile, write_blocklist_lines};

#[derive(Debug, Clone)]
pub(super) struct PartialMatch {
    pub(super) index: usize,
    pub(super) entry: String,
}

#[derive(Debug)]
pub(super) struct UnbanPlan {
    pub(super) target: String,
    pub(super) blocklist: BlocklistFile,
    pub(super) exact_indexes: Vec<usize>,
    pub(super) partial_matches: Vec<PartialMatch>,
    pub(super) remove_partial: bool,
}

impl UnbanPlan {
    pub(super) fn total_removal(&self) -> usize {
        self.exact_indexes.len()
            + if self.remove_partial {
                self.partial_matches.len()
            } else {
                0
            }
    }
}

#[derive(Debug)]
pub(super) struct UnbanResult {
    pub(super) removed_exact: usize,
    pub(super) removed_partial: usize,
}

impl UnbanResult {
    pub(super) fn total(&self) -> usize {
        self.removed_exact + self.removed_partial
    }
}

pub(super) fn build_unban_plan(path: &Path, input: &str) -> Result<UnbanPlan, KidoboError> {
    let canonical = parse_blocklist_target(input)?;
    let blocklist = BlocklistFile::load(path)?;
    let mut exact_indexes = Vec::new();
    let mut partial_matches = Vec::new();

    for (idx, line) in blocklist.lines.iter().enumerate() {
        if let Some(entry) = &line.canonical {
            if entry == &canonical {
                exact_indexes.push(idx);
            } else if canonical_overlaps(entry, &canonical) {
                partial_matches.push(PartialMatch {
                    index: idx,
                    entry: entry.to_string(),
                });
            }
        }
    }

    Ok(UnbanPlan {
        target: canonical.to_string(),
        blocklist,
        exact_indexes,
        partial_matches,
        remove_partial: false,
    })
}

pub(super) fn apply_unban_plan(path: &Path, plan: &UnbanPlan) -> Result<UnbanResult, KidoboError> {
    let mut removal_indexes: HashSet<usize> = plan.exact_indexes.iter().copied().collect();
    if plan.remove_partial {
        for partial in &plan.partial_matches {
            removal_indexes.insert(partial.index);
        }
    }

    if removal_indexes.is_empty() {
        return Ok(UnbanResult {
            removed_exact: 0,
            removed_partial: 0,
        });
    }

    let kept_lines = plan
        .blocklist
        .lines
        .iter()
        .enumerate()
        .filter_map(|(idx, line)| {
            if removal_indexes.contains(&idx) {
                None
            } else {
                Some(line.original.clone())
            }
        })
        .collect::<Vec<_>>();

    write_blocklist_lines(path, &kept_lines)?;

    let removed_partial = if plan.remove_partial {
        plan.partial_matches.len()
    } else {
        0
    };

    Ok(UnbanResult {
        removed_exact: plan.exact_indexes.len(),
        removed_partial,
    })
}

pub(super) fn parse_blocklist_target(input: &str) -> Result<CanonicalCidr, KidoboError> {
    let token = input.trim();
    parse_ip_cidr_non_strict(token).ok_or_else(|| KidoboError::BlocklistTargetParse {
        input: input.to_string(),
    })
}

fn canonical_overlaps(entry: &CanonicalCidr, target: &CanonicalCidr) -> bool {
    cidr_overlaps(*entry, *target)
}
