use std::env;
use std::fmt;
use std::fs;
use std::io;
use std::io::Cursor;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;

use mailparse::parse_mail;
use mailparse::MailHeaderMap;
use mailparse::MailParseError;
use mailparse::ParsedMail;
use zip::ZipArchive;

mod dmarc;
mod ui;

use dmarc::Feedback;
use zip::result::ZipError;

use crate::dmarc::Record;

#[derive(Debug)]
enum Error {
    MissingSubject,
    ParseMail(MailParseError),
    ExtractZip(ZipError),
    ReadXmlFromZip(io::Error),
    ReadMboxFile(PathBuf, io::Error),
    ParseDmarcReport(serde_xml_rs::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MissingSubject => write!(f, "Could not parse subject from email"),
            Error::ParseMail(e) => write!(f, "Could not parse email in mbox file: {e}"),
            Error::ExtractZip(e) => write!(f, "Failed to extract ZIP file from email: {e}"),
            Error::ReadXmlFromZip(e) => {
                write!(f, "Unable to extract XML report from ZIP file: {e}")
            }
            Error::ReadMboxFile(path, e) => {
                write!(f, "Could not read mbox file '{}': {}", path.display(), e)
            }
            Error::ParseDmarcReport(e) => write!(f, "Failed to parse XML as DMARC report: {e}"),
        }
    }
}

impl std::error::Error for Error {}

/// Extracts the XML file contained in the ZIP attachment of the provided email part.
fn extract_xml_from_zip(part: &ParsedMail) -> Result<String, Error> {
    let body = part.get_body_raw().map_err(Error::ParseMail)?;
    let cursor = Cursor::new(body.as_slice());
    let mut archive = ZipArchive::new(cursor).map_err(Error::ExtractZip)?;
    let mut xml_file = archive.by_index(0).map_err(Error::ExtractZip)?;
    let mut xml = String::new();
    xml_file
        .read_to_string(&mut xml)
        .map_err(Error::ReadXmlFromZip)?;
    Ok(xml)
}

fn get_feedbacks_from_mbox(path: &Path) -> Result<Vec<Feedback>, Error> {
    let content = fs::read_to_string(path).map_err(|e| Error::ReadMboxFile(path.into(), e))?;
    // Not conformant to RFC4155
    let mut feedbacks = vec![];
    let emails = content.split("From ");
    for email in emails.skip(1) {
        let parsed_mail = parse_mail(email.as_bytes()).map_err(Error::ParseMail)?;
        let subject = parsed_mail
            .get_headers()
            .get_first_value("Subject")
            .ok_or(Error::MissingSubject)?;
        println!("Processing email with subject '{subject}'");
        let zip_part = parsed_mail
            .parts()
            .find(|part| part.ctype.mimetype == "application/zip");
        match zip_part {
            Some(part) => {
                let xml = extract_xml_from_zip(part)?;
                let feedback: Feedback =
                    serde_xml_rs::from_str(&xml).map_err(Error::ParseDmarcReport)?;
                feedbacks.push(feedback);
            }
            None => eprintln!("Email does not contain a zipped report"),
        }
    }
    Ok(feedbacks)
}

fn run_list(feedbacks: Vec<Feedback>) {
    // Print each feedback
    for feedback in feedbacks {
        println!("{feedback}");
    }
}
fn run_aggregate(feedbacks: Vec<Feedback>) {
    if feedbacks.is_empty() {
        return;
    }

    let begin = feedbacks
        .iter()
        .map(|f| f.report_metadata.date_range.begin)
        .min()
        .unwrap();
    let end = feedbacks
        .iter()
        .map(|f| f.report_metadata.date_range.end)
        .max()
        .unwrap();
    println!(" Aggregate Report Details");
    println!("--------------------------");
    println!("Timeframe: {} to {}", begin, end);
    println!();

    let records: Vec<Record> = feedbacks.into_iter().flat_map(|f| f.records).collect();
    let table = ui::build_records_table(&records);
    println!("{table}");
}

fn try_main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage `dagger mbox_file_path [--aggregate]`");
        return Ok(());
    }

    // Gather feedback
    let path = PathBuf::from(&args[1]);
    let mut feedbacks = get_feedbacks_from_mbox(&path)?;

    // Sort and dedup feedbacks
    feedbacks.sort_by_key(|feedback| feedback.report_metadata.date_range.begin);
    feedbacks.dedup_by(|a, b| a.report_metadata.report_id == b.report_metadata.report_id);

    match args.get(2).map(|s| s.as_str()) {
        Some("--aggregate") => run_aggregate(feedbacks),
        Some(arg) => eprintln!("Invalid argument '{arg}'"),
        None => run_list(feedbacks),
    };

    Ok(())
}

fn main() {
    if let Err(e) = try_main() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
