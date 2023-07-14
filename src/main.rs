use std::env;
use std::fmt;
use std::fs;
use std::io::Cursor;
use std::io::Read;
use std::path::PathBuf;

use mailparse::parse_mail;
use mailparse::MailHeaderMap;
use mailparse::ParsedMail;
use zip::ZipArchive;

mod dmarc;

use dmarc::Feedback;

#[derive(Debug)]
enum Error {
    MissingSubject,
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
