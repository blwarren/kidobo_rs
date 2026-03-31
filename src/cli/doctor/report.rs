use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DoctorOverall {
    #[serde(rename = "OK")]
    Ok,
    #[serde(rename = "FAIL")]
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DoctorCheckStatus {
    #[serde(rename = "OK")]
    Ok,
    #[serde(rename = "FAIL")]
    Fail,
    #[serde(rename = "SKIP")]
    Skip,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DoctorCheck {
    pub name: String,
    pub status: DoctorCheckStatus,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DoctorReport {
    pub overall: DoctorOverall,
    pub checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    pub(super) fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let overall = if checks
            .iter()
            .any(|check| check.status == DoctorCheckStatus::Fail)
        {
            DoctorOverall::Fail
        } else {
            DoctorOverall::Ok
        };

        Self { overall, checks }
    }
}

pub(super) fn ok_check(name: &'static str, detail: String) -> DoctorCheck {
    DoctorCheck {
        name: name.to_string(),
        status: DoctorCheckStatus::Ok,
        detail,
    }
}

pub(super) fn fail_check(name: &'static str, detail: String) -> DoctorCheck {
    DoctorCheck {
        name: name.to_string(),
        status: DoctorCheckStatus::Fail,
        detail,
    }
}

pub(super) fn skip_check(name: &'static str, detail: impl Into<String>) -> DoctorCheck {
    DoctorCheck {
        name: name.to_string(),
        status: DoctorCheckStatus::Skip,
        detail: detail.into(),
    }
}
