use std::net::IpAddr;

use chrono::serde::ts_seconds;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Feedback {
    /// Version is optional since not included in Google report.
    version: Option<f32>,
    report_metadata: ReportMetadata,
    policy_published: PolicyPublished,
    record: Vec<Record>,
}

/// The time range in UTC covered by messages in this report, specified in seconds since epoch.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct DateRange {
    #[serde(with = "ts_seconds")]
    begin: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    end: DateTime<Utc>,
}

/// Report generator metadata.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct ReportMetadata {
    org_name: String,
    email: String,
    extra_contact_info: Option<String>,
    report_id: String,
    date_range: DateRange,
    #[serde(default = "Default::default")]
    error: Vec<String>,
}

/// Alignment mode (relaxed or strict) for DKIM and SPF.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
enum Alignment {
    #[serde(rename = "r")]
    Relaxed,
    #[serde(rename = "s")]
    Strict,
}

/// The policy actions specified by p and sp in the DMARC record.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Disposition {
    None,
    Quarantine,
    Reject,
}

/// The DMARC policy that applied to the messages in this report.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct PolicyPublished {
    /// The domain at which the DMARC record was found.
    domain: String,
    /// The DKIM alignment mode.
    adkim: Option<Alignment>,
    /// The SPF alignment mode.
    aspf: Option<Alignment>,
    /// The policy to apply to messages from the domain.
    p: Disposition,
    /// The policy to apply to messages from subdomains.
    sp: Disposition,
    /// The percent of messages to which policy applies.
    pct: u8,
    /// Failure reporting options in effect.
    ///
    /// This is made optional since the Google report does not include this field.
    fo: Option<String>,
}

/// The DMARC-aligned authentication result.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum DmarcResult {
    Pass,
    Fail,
}

/// Reasons that may affect DMARC disposition or execution thereof.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum PolicyOverride {
    Forwarded,
    SampledOut,
    TrustedForwarder,
    MailingList,
    LocalPolicy,
    Other,
}

/// How do we allow report generators to include new classes of override reasons if they want to be more specific than "other"?
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct PolicyOverrideReason {
    #[serde(rename = "type")]
    typ: PolicyOverride,
    comment: Option<String>,
}

/// Taking into account everything else in the record, the results of applying DMARC.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct PolicyEvaluated {
    disposition: Disposition,
    dkim: DmarcResult,
    spf: DmarcResult,
    #[serde(default = "Default::default")]
    reason: Vec<PolicyOverrideReason>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Row {
    /// The connecting IP.
    source_ip: IpAddr,
    /// The number of matching messages.
    count: u32,
    /// The DMARC disposition applying to matching messages.
    policy_evaluated: PolicyEvaluated,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Identifier {
    /// The envelope recipient domain.
    envelope_to: Option<String>,
    /// The RFC5321.MailFrom domain.
    ///
    /// Also made optional since Google reports don't include it.
    envelope_from: Option<String>,
    /// The RFC5322.From domain.
    header_from: String,
}

/// DKIM verification result, according to RFC 7001 Section 2.6.1.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum DkimResult {
    None,
    Pass,
    Fail,
    Policy,
    Neutral,
    TempError,
    PermError,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct DkimAuthResult {
    /// The "d=" parameter in the signature.
    domain: String,
    /// The "s=" parameter in the signature.
    selector: Option<String>,
    /// The DKIM verification result.
    result: DkimResult,
    /// Any extra information (e.g., from Authentication-Results).
    human_result: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum SpfDomainScope {
    Helo,
    MFrom,
}

/// DKIM verification result, according to RFC 7001 Section 2.6.1.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum SpfResult {
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
struct SpfAuthResult {
    /// The checked domain.
    domain: String,
    /// The scope of the checked domain.
    ///
    /// Also made optional.
    scope: Option<SpfDomainScope>,
    /// The SPF verification result.
    result: SpfResult,
}

/// This element contains DKIM and SPF results, uninterpreted with respect to DMARC.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct AuthResult {
    /// There may be no DKIM signatures, or multiple DKIM signatures.
    #[serde(default = "Default::default")]
    dkim: Vec<DkimAuthResult>,
    /// There will always be at least one SPF result.
    spf: Vec<SpfAuthResult>,
}

/// This element contains all the authentication results that were evaluated by the receiving system for the given set of messages.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Record {
    row: Row,
    identifiers: Identifier,
    auth_results: AuthResult,
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
