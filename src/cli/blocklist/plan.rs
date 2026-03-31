use std::collections::HashSet;
use std::path::Path;

use crate::adapters::blocklist_file::{BlocklistDocument, write_blocklist_lines};
use crate::core::blocklist::{
    BlocklistTargetParseError, UnbanIndexPlan,
    parse_blocklist_target as parse_blocklist_target_core, plan_unban,
};
use crate::core::network::CanonicalCidr;
use crate::error::KidoboError;

#[derive(Debug, Clone)]
pub(super) struct PartialMatch {
    pub(super) index: usize,
    pub(super) entry: String,
}

#[derive(Debug)]
pub(super) struct UnbanPlan {
    pub(super) target: String,
    pub(super) blocklist: BlocklistDocument,
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
    let blocklist = BlocklistDocument::load(path)?;
    let line_canonicals = blocklist
        .lines
        .iter()
        .map(|line| line.canonical)
        .collect::<Vec<_>>();
    let index_plan = plan_unban(&line_canonicals, canonical);
    let partial_matches = partial_matches(&blocklist, &index_plan);

    Ok(UnbanPlan {
        target: canonical.to_string(),
        blocklist,
        exact_indexes: index_plan.exact_indexes,
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
                Some(line.original.as_str())
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
    parse_blocklist_target_core(input).map_err(|err| match err {
        BlocklistTargetParseError::Invalid => KidoboError::BlocklistTargetParse {
            input: input.to_string(),
        },
    })
}

fn partial_matches(blocklist: &BlocklistDocument, plan: &UnbanIndexPlan) -> Vec<PartialMatch> {
    let partial_indexes = plan.partial_indexes.iter().copied().collect::<HashSet<_>>();

    blocklist
        .lines
        .iter()
        .enumerate()
        .filter_map(|(idx, line)| {
            if !partial_indexes.contains(&idx) {
                return None;
            }

            line.canonical.map(|canonical| PartialMatch {
                index: idx,
                entry: canonical.to_string(),
            })
        })
        .collect()
}
