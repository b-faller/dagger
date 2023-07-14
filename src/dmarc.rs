use std::net::IpAddr;

use chrono::serde::ts_seconds;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Feedback {
    /// Version is optional since not included in Google report.
    pub version: Option<f32>,
    pub report_metadata: ReportMetadata,
    pub policy_published: PolicyPublished,
    #[serde(rename = "record")]
    pub records: Vec<Record>,
}

/// The time range in UTC covered by messages in this report, specified in seconds since epoch.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct DateRange {
    #[serde(with = "ts_seconds")]
    pub begin: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub end: DateTime<Utc>,
}

/// Report generator metadata.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ReportMetadata {
    pub org_name: String,
    pub email: String,
    pub extra_contact_info: Option<String>,
    pub report_id: String,
    pub date_range: DateRange,
    #[serde(rename = "error", default = "Default::default")]
    pub errors: Vec<String>,
}

/// Alignment mode (relaxed or strict) for DKIM and SPF.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum Alignment {
    #[serde(rename = "r")]
    Relaxed,
    #[serde(rename = "s")]
    Strict,
}

/// The policy actions specified by p and sp in the DMARC record.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    None,
    Quarantine,
    Reject,
}

/// The DMARC policy that applied to the messages in this report.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PolicyPublished {
    /// The domain at which the DMARC record was found.
    pub domain: String,
    /// The DKIM alignment mode.
    pub adkim: Option<Alignment>,
    /// The SPF alignment mode.
    pub aspf: Option<Alignment>,
    /// The policy to apply to messages from the domain.
    pub p: Disposition,
    /// The policy to apply to messages from subdomains.
    pub sp: Disposition,
    /// The percent of messages to which policy applies.
    pub pct: u8,
    /// Failure reporting options in effect.
    ///
    /// This is made optional since the Google report does not include this field.
    pub fo: Option<String>,
}

/// The DMARC-aligned authentication result.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DmarcResult {
    Pass,
    Fail,
}

/// Reasons that may affect DMARC disposition or execution thereof.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOverride {
    Forwarded,
    SampledOut,
    TrustedForwarder,
    MailingList,
    LocalPolicy,
    Other,
}

/// How do we allow report generators to include new classes of override reasons if they want to be more specific than "other"?
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PolicyOverrideReason {
    #[serde(rename = "type")]
    pub typ: PolicyOverride,
    pub comment: Option<String>,
}

/// Taking into account everything else in the record, the results of applying DMARC.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PolicyEvaluated {
    pub disposition: Disposition,
    pub dkim: DmarcResult,
    pub spf: DmarcResult,
    #[serde(rename = "reason", default = "Default::default")]
    pub reasons: Vec<PolicyOverrideReason>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Row {
    /// The connecting IP.
    pub source_ip: IpAddr,
    /// The number of matching messages.
    pub count: u32,
    /// The DMARC disposition applying to matching messages.
    pub policy_evaluated: PolicyEvaluated,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Identifier {
    /// The envelope recipient domain.
    pub envelope_to: Option<String>,
    /// The RFC5321.MailFrom domain.
    ///
    /// Also made optional since Google reports don't include it.
    pub envelope_from: Option<String>,
    /// The RFC5322.From domain.
    pub header_from: String,
}

/// DKIM verification result, according to RFC 7001 Section 2.6.1.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DkimResult {
    None,
    Pass,
    Fail,
    Policy,
    Neutral,
    TempError,
    PermError,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct DkimAuthResult {
    /// The "d=" parameter in the signature.
    pub domain: String,
    /// The "s=" parameter in the signature.
    pub selector: Option<String>,
    /// The DKIM verification result.
    pub result: DkimResult,
    /// Any extra information (e.g., from Authentication-Results).
    pub human_result: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SpfDomainScope {
    Helo,
    MFrom,
}

/// DKIM verification result, according to RFC 7001 Section 2.6.1.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SpfResult {
    None,
    Neutral,
    Pass,
    Fail,
    Softfail,
    /// "TempError" commonly implemented as "unknown".
    TempError,
    /// "PermError" commonly implemented as "error".
    PermError,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct SpfAuthResult {
    /// The checked domain.
    pub domain: String,
    /// The scope of the checked domain.
    ///
    /// Also made optional.
    pub scope: Option<SpfDomainScope>,
    /// The SPF verification result.
    pub result: SpfResult,
}

/// This element contains DKIM and SPF results, uninterpreted with respect to DMARC.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct AuthResult {
    /// There may be no DKIM signatures, or multiple DKIM signatures.
    #[serde(default = "Default::default")]
    pub dkim: Vec<DkimAuthResult>,
    /// There will always be at least one SPF result.
    pub spf: Vec<SpfAuthResult>,
}

/// This element contains all the authentication results that were evaluated by the receiving system for the given set of messages.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Record {
    pub row: Row,
    pub identifiers: Identifier,
    pub auth_results: AuthResult,
}

#[cfg(test)]
mod tests {
    use super::SpfDomainScope;

    #[test]
    fn deserialize_spf_domain_scope() {
        let scope: SpfDomainScope = serde_xml_rs::from_str("<mfrom></mfrom>").unwrap();
        assert_eq!(scope, SpfDomainScope::MFrom);
        let scope: SpfDomainScope = serde_xml_rs::from_str("<helo></helo>").unwrap();
        assert_eq!(scope, SpfDomainScope::Helo);
    }
}
