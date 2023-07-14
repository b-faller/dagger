use std::env;
use std::fmt;
use std::fs;
use std::io::Cursor;
use std::io::Read;
use std::net::IpAddr;
use std::path::PathBuf;

use mailparse::parse_mail;
use mailparse::MailHeaderMap;
use mailparse::ParsedMail;
use serde::{Deserialize, Serialize};
use zip::ZipArchive;

#[derive(Debug)]
enum Error {
    MissingSubject,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Feedback {
    report_metadata: ReportMetadata,
    policy_published: PolicyPublished,
    record: Vec<Record>,
}

/// The time range in UTC covered by messages in this report, specified in seconds since epoch.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct DateRange {
    begin: i32,
    end: i32,
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
#[serde(rename_all = "lowercase")]
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
    pct: i32,
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
    envelope_from: Option<String>,
    /// The RFC5322.From domain.
    header_from: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum DKIMResult {
    None,
    Pass,
    Fail,
    Policy,
    Neutral,
    TempError,
    PermError,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct DKIMAuthResult {
    /// The "d=" parameter in the signature.
    d: Option<String>,
    /// The "s=" parameter in the signature.
    s: Option<String>,
    /// The DKIM verification result.
    result: DKIMResult,
    /// Any extra information (e.g., from Authentication-Results).
    human_result: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum SPFDomainScope {
    Helo,
    MFrom,
}

/// DKIM verification result, according to RFC 7001 Section 2.6.1.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum SPFResult {
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
struct SPFAuthResult {
    /// The checked domain.
    domain: String,
    /// The scope of the checked domain.
    scope: Option<SPFDomainScope>,
    /// The SPF verification result.
    result: SPFResult,
}

/// This element contains DKIM and SPF results, uninterpreted with respect to DMARC.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct AuthResult {
    /// There may be no DKIM signatures, or multiple DKIM signatures.
    #[serde(default = "Default::default")]
    dkim: Vec<DKIMAuthResult>,
    /// There will always be at least one SPF result.
    spf: Vec<SPFAuthResult>,
}

/// This element contains all the authentication results that were evaluated by the receiving system for the given set of messages.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Record {
    row: Row,
    identifiers: Identifier,
    auth_results: AuthResult,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MissingSubject => write!(f, "Could not parse subject from email"),
        }
    }
}

impl std::error::Error for Error {}

/// Extracts the XML file contained in the ZIP attachment of the provided email part.
fn extract_xml_from_zip(part: &ParsedMail) -> Result<String, Box<dyn std::error::Error>> {
    println!("{}", part.ctype.mimetype);
    let body = part.get_body_raw()?;
    let cursor = Cursor::new(body.as_slice());
    let mut archive = ZipArchive::new(cursor)?;
    let mut xml_file = archive.by_index(0)?;
    let mut xml = String::new();
    xml_file.read_to_string(&mut xml)?;
    Ok(xml)
}

fn parse_report(xml: String) -> Result<Feedback, Box<dyn std::error::Error>> {
    println!("{}", xml);
    let feedback = serde_xml_rs::from_str(&xml)?;
    Ok(feedback)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage `dagger mbox_path`");
        return Ok(());
    }

    let path = PathBuf::from(&args[1]);
    let content = fs::read_to_string(path)?;

    // Not conformant to RFC4155
    let emails = content.split("From ");
    for email in emails.skip(1) {
        let parsed_mail = parse_mail(email.as_bytes())?;
        let subject = parsed_mail
            .get_headers()
            .get_first_value("Subject")
            .ok_or(Error::MissingSubject)?;
        println!("Processing email with subject '{subject}'");

        for part in parsed_mail.parts() {
            if part.ctype.mimetype == "application/zip" {
                let xml = extract_xml_from_zip(part)?;
                let report = parse_report(xml);
                println!("{:?}", report);
            }
        }
    }

    Ok(())
}
