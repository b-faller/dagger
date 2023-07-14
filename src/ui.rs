use std::fmt::Display;

use tabled::{
    builder::Builder,
    settings::{Color, Modify, Style},
    Table,
};

use crate::dmarc::{
    DateRange, DkimAuthResult, DmarcResult, Feedback, PolicyOverrideReason, Record, SpfAuthResult,
};

impl Display for DateRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} to {}", self.begin, self.end)
    }
}

impl Display for DkimAuthResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} (", self.result)?;
        write!(f, "d={}", self.domain)?;
        if let Some(selector) = &self.selector {
            write!(f, ", selector={selector}")?;
        }
        if let Some(human_result) = &self.human_result {
            write!(f, ", human_result={human_result}")?;
        }
        write!(f, ")")?;
        Ok(())
    }
}

impl Display for SpfAuthResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} (", self.result)?;
        write!(f, "d={}", self.domain)?;
        if let Some(scope) = &self.scope {
            write!(f, ", scope={scope:?}")?;
        }
        write!(f, ")")?;
        Ok(())
    }
}

impl Display for PolicyOverrideReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.typ)?;
        if let Some(comment) = &self.comment {
            write!(f, " ({comment})")?;
        }
        Ok(())
    }
}

impl Display for Feedback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, " DMARC Report Details")?;
        writeln!(f, "----------------------")?;
        if let Some(version) = &self.version {
            writeln!(f, "Version: {}", version)?;
        }
        writeln!(f, "Provider: {}", self.report_metadata.org_name)?;
        writeln!(f, "Coverage: {}", self.report_metadata.date_range)?;
        writeln!(f, "Report ID: {}", self.report_metadata.report_id)?;
        writeln!(f, "Email contact: {}", self.report_metadata.email)?;
        if let Some(info) = &self.report_metadata.extra_contact_info {
            writeln!(f, "Extra contact: {}", info)?;
        }
        writeln!(f, "Errors: {:?}", self.report_metadata.errors)?;
        writeln!(f)?;

        writeln!(f, " Policy Details")?;
        writeln!(f, "----------------")?;
        writeln!(f, "Policy: {:?}", self.policy_published.p)?;
        writeln!(f, "Sub-domain policy: {:?}", self.policy_published.sp)?;
        if let Some(adkim) = &self.policy_published.adkim {
            writeln!(f, "DKIM alignment: {:?}", adkim)?;
        }
        if let Some(aspf) = &self.policy_published.aspf {
            writeln!(f, "SPF alignment: {:?}", aspf)?;
        }
        writeln!(f, "Percentage: {}", self.policy_published.pct)?;
        if let Some(failure_options) = &self.policy_published.fo {
            writeln!(f, "Failure options: {:?}", failure_options)?;
        }
        writeln!(f)?;

        let table = build_records_table(&self.records);
        writeln!(f, "{}", table)?;

        Ok(())
    }
}

fn get_dmarc_color(result: &DmarcResult) -> Color {
    match result {
        DmarcResult::Pass => Color::FG_BRIGHT_GREEN,
        DmarcResult::Fail => Color::FG_BRIGHT_RED,
    }
}

pub fn build_records_table(records: &[Record]) -> Table {
    let mut builder = Builder::default();
    builder.set_header([
        "From domain",
        "IP address",
        "Count",
        "Disposition",
        "Override Reasons",
        "DKIM",
        "SPF",
        "DKIM Auth Result",
        "SPF Auth Result",
    ]);

    for r in records {
        let header_from = &r.identifiers.header_from;
        let source_ip = r.row.source_ip;
        let count = r.row.count;
        let disposition = format!("{:?}", r.row.policy_evaluated.disposition);
        let override_reasons = &r
            .row
            .policy_evaluated
            .reasons
            .iter()
            .map(|reason| reason.to_string())
            .collect::<Vec<String>>()
            .join(", ");
        let dkim_alignement = format!("{:?}", r.row.policy_evaluated.dkim);
        let spf_alignement = format!("{:?}", r.row.policy_evaluated.spf);
        let dkim_auth_results = r
            .auth_results
            .dkim
            .iter()
            .map(|res| res.to_string())
            .collect::<Vec<String>>()
            .join(", ");
        let spf_auth_results = r
            .auth_results
            .spf
            .iter()
            .map(|res| res.to_string())
            .collect::<Vec<String>>()
            .join(", ");
        builder.push_record([
            header_from,
            &source_ip.to_string(),
            &count.to_string(),
            &disposition,
            override_reasons,
            &dkim_alignement,
            &spf_alignement,
            &dkim_auth_results,
            &spf_auth_results,
        ]);
    }

    let mut table = builder.build();
    table.with(Style::psql());

    // Highlight cells
    for (i, r) in records.iter().enumerate() {
        let dkim_alignement = get_dmarc_color(&r.row.policy_evaluated.dkim);
        table.with(Modify::new((i + 1, 5)).with(dkim_alignement));
        let spf_alignement = get_dmarc_color(&r.row.policy_evaluated.spf);
        table.with(Modify::new((i + 1, 6)).with(spf_alignement));
    }

    table
}
