use anyhow::{Context, Result, anyhow, bail};
use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};
use rayon::prelude::*;
use regex::Regex;
use reqwest::StatusCode;
use reqwest::blocking::Client;
use scraper::{Html, Selector};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

const BASE_URL: &str = "https://csrc.nist.gov";
const CMVP_SEARCH_URL: &str = "https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search";
const CMVP_SEARCH_ALL_URL: &str = "https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search/all";
const CAVP_SEARCH_URL: &str =
    "https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/validation-search";
const ESV_SEARCH_URL: &str = "https://csrc.nist.gov/projects/cryptographic-module-validation-program/entropy-validations/search";
const USER_AGENT: &str = "cmvp-algorithm-products-rust/1.0 (+https://csrc.nist.gov/)";
const CACHE_DIR_NAME: &str = "cmvp_search_cache";
const POLICY_SCAN_WORKERS: usize = 4;

#[derive(Parser, Debug)]
#[command(
    about = "Search NIST CMVP validated modules by algorithm or ESV certificates by IID claim.",
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<SearchCommand>,

    #[command(flatten)]
    modules: ModuleArgs,
}

#[derive(Subcommand, Debug)]
enum SearchCommand {
    Modules(ModuleArgs),
    Esv(EsvArgs),
}

#[derive(ClapArgs, Debug)]
struct ModuleArgs {
    #[arg(required = true)]
    algorithms: Vec<String>,

    #[arg(long, default_value = "Active", value_parser = ["Active", "Historical", "Revoked"])]
    status: String,

    #[arg(long)]
    include_revoked: bool,

    #[arg(long)]
    no_policy_scan: bool,

    #[arg(long)]
    fresh: bool,

    #[arg(long, default_value = CACHE_DIR_NAME)]
    cache_dir: PathBuf,

    #[arg(long)]
    offline: bool,

    #[arg(long)]
    csv: Option<PathBuf>,

    #[arg(long)]
    json: Option<PathBuf>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum IidClaimFilter {
    Any,
    Iid,
    NonIid,
    Unknown,
}

impl IidClaimFilter {
    fn as_str(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Iid => "iid",
            Self::NonIid => "non-iid",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(ClapArgs, Debug)]
struct EsvArgs {
    #[arg(long, value_enum, default_value_t = IidClaimFilter::Any)]
    iid: IidClaimFilter,

    #[arg(long)]
    fresh: bool,

    #[arg(long, default_value = CACHE_DIR_NAME)]
    cache_dir: PathBuf,

    #[arg(long)]
    offline: bool,

    #[arg(long)]
    csv: Option<PathBuf>,

    #[arg(long)]
    json: Option<PathBuf>,
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum IidClaim {
    Iid,
    NonIid,
    #[default]
    Unknown,
}

impl IidClaim {
    fn as_str(self) -> &'static str {
        match self {
            Self::Iid => "iid",
            Self::NonIid => "non-iid",
            Self::Unknown => "unknown",
        }
    }

    fn matches_filter(self, filter: IidClaimFilter) -> bool {
        matches!(filter, IidClaimFilter::Any)
            || matches!(
                (self, filter),
                (Self::Iid, IidClaimFilter::Iid)
                    | (Self::NonIid, IidClaimFilter::NonIid)
                    | (Self::Unknown, IidClaimFilter::Unknown)
            )
    }
}

#[derive(Copy, Clone, Debug)]
enum OutputKind {
    Cmvp,
    Esv,
}

#[derive(Clone, Debug, Default, Serialize)]
struct ResultRow {
    module_certificate: String,
    vendor: String,
    module_name: String,
    module_type: String,
    validation_date: String,
    certificate_url: String,
    policy_url: String,
    cavp_certificate: String,
    cavp_algorithm: String,
    operation: String,
    properties: String,
    cavp_listed: bool,
    esv_standard: String,
    esv_description: String,
    esv_noise_source: String,
    esv_reuse_status: String,
    entropy_document_url: String,
    iid_claim: IidClaim,
}

#[derive(Serialize)]
struct JsonOutput {
    query: String,
    canonical_query: String,
    results_message: String,
    results: Vec<ResultRow>,
}

#[derive(Clone, Debug)]
struct SearchOutcome {
    query: String,
    canonical_query: String,
    results_message: String,
    rows: Vec<ResultRow>,
    kind: OutputKind,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    rayon::ThreadPoolBuilder::new()
        .num_threads(POLICY_SCAN_WORKERS)
        .build_global()
        .ok();

    let client = Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(60))
        .build()
        .context("failed to build HTTP client")?;

    let command = cli.command.unwrap_or(SearchCommand::Modules(cli.modules));
    let (outcomes, csv_path, json_path) = match command {
        SearchCommand::Modules(args) => {
            let outcomes = run_module_search(&client, &args)?;
            (outcomes, args.csv, args.json)
        }
        SearchCommand::Esv(args) => {
            let outcomes = run_esv_search(&client, &args)?;
            (outcomes, args.csv, args.json)
        }
    };

    for outcome in &outcomes {
        render_table(outcome);
    }

    if let Some(path) = csv_path.as_ref() {
        write_csv(path, &outcomes)?;
    }
    if let Some(path) = json_path.as_ref() {
        write_json(path, &outcomes)?;
    }

    Ok(())
}

fn run_module_search(client: &Client, args: &ModuleArgs) -> Result<Vec<SearchOutcome>> {
    let cmvp_algorithm_options = if args.offline {
        HashMap::new()
    } else {
        fetch_cmvp_algorithm_options(client)?
    };
    let cavp_algorithms = if args.offline {
        Vec::new()
    } else {
        fetch_cavp_active_algorithms(client)?
    };
    search_products_for_terms(
        client,
        &args.algorithms,
        &cmvp_algorithm_options,
        &cavp_algorithms,
        &args.status,
        args.include_revoked,
        !args.no_policy_scan,
        args.fresh,
        &args.cache_dir,
        args.offline,
    )
}

fn run_esv_search(client: &Client, args: &EsvArgs) -> Result<Vec<SearchOutcome>> {
    if !document_scan_supported(&args.cache_dir, "entropy-documents") {
        bail!("pdftotext is not installed, so ESV IID classification is unavailable.");
    }

    fs::create_dir_all(&args.cache_dir)?;
    let catalog = fetch_esv_catalog(client, &args.cache_dir, args.offline)?;
    let scanned_certificates = catalog.len();
    let classified_rows: Vec<ResultRow> = catalog
        .par_iter()
        .map(|row| enrich_esv_certificate(client, &args.cache_dir, row, args.fresh))
        .collect::<Result<Vec<_>>>()?;

    let unknown_count = classified_rows
        .iter()
        .filter(|row| row.iid_claim == IidClaim::Unknown)
        .count();
    let mut rows: Vec<ResultRow> = classified_rows
        .into_iter()
        .filter(|row| row.iid_claim.matches_filter(args.iid))
        .collect();
    rows.sort_by(|a, b| b.module_certificate.cmp(&a.module_certificate));

    let results_message = format!(
        "Scanned {scanned_certificates} ESV certificates; matched {} with IID filter '{}' ({} unknown).",
        rows.len(),
        args.iid.as_str(),
        unknown_count
    );

    Ok(vec![SearchOutcome {
        query: "esv".to_string(),
        canonical_query: args.iid.as_str().to_string(),
        results_message,
        rows,
        kind: OutputKind::Esv,
    }])
}

fn fetch_with_retries(client: &Client, url: &str, query: &[(&str, &str)]) -> Result<Vec<u8>> {
    let mut last_error = None;
    for attempt in 0..4 {
        let response = client.get(url).query(query).send();
        match response {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    return Ok(resp
                        .bytes()
                        .context("failed to read response body")?
                        .to_vec());
                }
                if !matches!(
                    status,
                    StatusCode::REQUEST_TIMEOUT
                        | StatusCode::TOO_MANY_REQUESTS
                        | StatusCode::INTERNAL_SERVER_ERROR
                        | StatusCode::BAD_GATEWAY
                        | StatusCode::SERVICE_UNAVAILABLE
                        | StatusCode::GATEWAY_TIMEOUT
                ) || attempt == 3
                {
                    bail!("request failed for {url}: {status}");
                }
                last_error = Some(anyhow!("request failed for {url}: {status}"));
            }
            Err(err) => {
                if attempt == 3 {
                    return Err(err).with_context(|| format!("request failed for {url}"));
                }
                last_error = Some(anyhow!(err));
            }
        }
        thread::sleep(Duration::from_millis(1500 * (attempt + 1) as u64));
    }
    Err(last_error.unwrap_or_else(|| anyhow!("request failed for {url}")))
}

fn fetch_text(client: &Client, url: &str, query: &[(&str, &str)]) -> Result<String> {
    Ok(String::from_utf8_lossy(&fetch_with_retries(client, url, query)?).into_owned())
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    Ok(())
}

fn write_bytes(path: &Path, data: &[u8]) -> Result<()> {
    ensure_parent_dir(path)?;
    fs::write(path, data).with_context(|| format!("failed to write {}", path.display()))
}

fn write_text(path: &Path, data: &str) -> Result<()> {
    ensure_parent_dir(path)?;
    fs::write(path, data).with_context(|| format!("failed to write {}", path.display()))
}

fn cache_html_document(
    client: &Client,
    cache_dir: &Path,
    subdir: &str,
    document_url: &str,
    document_name: &str,
    fresh: bool,
) -> Result<String> {
    let path = cache_dir.join(subdir).join(format!("{document_name}.html"));
    if path.exists() && !fresh {
        return fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()));
    }
    let html = fetch_text(client, document_url, &[])?;
    write_text(&path, &html)?;
    Ok(html)
}

fn cache_certificate_html(
    client: &Client,
    cache_dir: &Path,
    certificate_url: &str,
    module_certificate: &str,
    fresh: bool,
) -> Result<String> {
    cache_html_document(
        client,
        cache_dir,
        "certificates",
        certificate_url,
        module_certificate,
        fresh,
    )
}

fn cache_esv_certificate_html(
    client: &Client,
    cache_dir: &Path,
    certificate_url: &str,
    certificate: &str,
    fresh: bool,
) -> Result<String> {
    cache_html_document(
        client,
        cache_dir,
        "esv-certificates",
        certificate_url,
        certificate,
        fresh,
    )
}

fn cached_document_paths(cache_dir: &Path, subdir: &str, document_url: &str) -> (PathBuf, PathBuf) {
    let filename = Path::new(document_url)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let pdf_path = cache_dir.join(subdir).join(filename);
    let txt_path = pdf_path.with_extension("txt");
    (pdf_path, txt_path)
}

fn extract_cached_pdf_text(
    client: &Client,
    cache_dir: &Path,
    subdir: &str,
    document_url: &str,
    fresh: bool,
) -> Result<String> {
    let (pdf_path, txt_path) = cached_document_paths(cache_dir, subdir, document_url);
    if txt_path.exists() && !fresh {
        return fs::read_to_string(&txt_path)
            .with_context(|| format!("failed to read {}", txt_path.display()));
    }
    if !pdf_path.exists() || fresh {
        write_bytes(&pdf_path, &fetch_with_retries(client, document_url, &[])?)?;
    }
    ensure_parent_dir(&txt_path)?;
    let output = Command::new("pdftotext")
        .arg(&pdf_path)
        .arg(&txt_path)
        .output()
        .context("failed to invoke pdftotext")?;
    if !output.status.success() {
        bail!(
            "pdftotext failed for {}: {}",
            pdf_path.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    fs::read_to_string(&txt_path).with_context(|| format!("failed to read {}", txt_path.display()))
}

fn extract_pdf_text(
    client: &Client,
    cache_dir: &Path,
    policy_url: &str,
    fresh: bool,
) -> Result<String> {
    extract_cached_pdf_text(client, cache_dir, "security-policies", policy_url, fresh)
}

fn normalize_for_match(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

fn compile_term_pattern(term: &str) -> Result<Regex> {
    Regex::new(&format!(
        r"(?i)(^|[^A-Za-z0-9])({})([^A-Za-z0-9]|$)",
        regex::escape(term)
    ))
    .context("failed to compile term regex")
}

fn text_of(element: scraper::ElementRef<'_>) -> String {
    element
        .text()
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn first_non_empty_text(element: scraper::ElementRef<'_>) -> String {
    element
        .text()
        .map(str::trim)
        .find(|value| !value.is_empty())
        .unwrap_or_default()
        .to_string()
}

fn selector(value: &str) -> Result<Selector> {
    Selector::parse(value).map_err(|_| anyhow!("invalid selector: {value}"))
}

fn absolute_url(href: &str) -> String {
    if href.starts_with("http://") || href.starts_with("https://") {
        href.to_string()
    } else {
        format!("{BASE_URL}{href}")
    }
}

fn fetch_cmvp_algorithm_options(client: &Client) -> Result<HashMap<String, String>> {
    let html = Html::parse_document(&fetch_text(client, CMVP_SEARCH_URL, &[])?);
    let option_selector = selector("#Algorithm option")?;
    let mut options = HashMap::new();
    for option in html.select(&option_selector) {
        let value = option.value().attr("value").unwrap_or("").trim();
        let text = text_of(option);
        if value.is_empty() {
            continue;
        }
        options.insert(value.to_lowercase(), value.to_string());
        if !text.is_empty() {
            options.insert(text.to_lowercase(), value.to_string());
        }
    }
    if options.is_empty() {
        bail!("could not parse the CMVP algorithm list");
    }
    Ok(options)
}

fn fetch_cavp_active_algorithms(client: &Client) -> Result<Vec<String>> {
    let html = Html::parse_document(&fetch_text(client, CAVP_SEARCH_URL, &[])?);
    let option_selector = selector("#search-algorithm optgroup[label=\"Active\"] option")?;
    let algorithms: Vec<String> = html
        .select(&option_selector)
        .map(text_of)
        .filter(|value| !value.is_empty())
        .collect();
    if algorithms.is_empty() {
        bail!("could not parse the CAVP active algorithm list");
    }
    Ok(algorithms)
}

fn resolve_cavp_algorithms(term: &str, cavp_algorithms: &[String]) -> Vec<String> {
    let exact: Vec<String> = cavp_algorithms
        .iter()
        .filter(|algorithm| algorithm.eq_ignore_ascii_case(term))
        .cloned()
        .collect();
    if !exact.is_empty() {
        return exact;
    }

    let normalized_term = normalize_for_match(term);
    let mut matches: Vec<String> = cavp_algorithms
        .iter()
        .filter(|algorithm| {
            !normalized_term.is_empty() && normalize_for_match(algorithm).contains(&normalized_term)
        })
        .cloned()
        .collect();
    matches.sort();
    matches
}

fn normalize_cmvp_algorithm(
    term: &str,
    options: &HashMap<String, String>,
) -> Result<(String, String)> {
    let normalized = term.trim();
    if normalized.is_empty() {
        bail!("algorithm names must not be empty");
    }
    if let Some(canonical) = options.get(&normalized.to_lowercase()) {
        return Ok(("Algorithm".to_string(), canonical.clone()));
    }
    Ok(("OtherAlgorithms".to_string(), normalized.to_string()))
}

fn parse_results_page(html_text: &str) -> Result<(Vec<ResultRow>, String)> {
    let html = Html::parse_document(html_text);
    let results_selector = selector("p#resultsMessage")?;
    let error_selector = selector("p#errorMessage")?;
    let row_selector = selector("#searchResultsTable tbody tr")?;
    let td_selector = selector("td")?;
    let a_selector = selector("a")?;

    let message = html
        .select(&results_selector)
        .next()
        .map(text_of)
        .or_else(|| html.select(&error_selector).next().map(text_of))
        .unwrap_or_default();

    let mut rows = Vec::new();
    for row in html.select(&row_selector) {
        let cells: Vec<_> = row.select(&td_selector).collect();
        if cells.len() < 5 {
            continue;
        }
        let certificate_link = cells[0]
            .select(&a_selector)
            .next()
            .and_then(|a| a.value().attr("href"))
            .map(absolute_url)
            .unwrap_or_default();
        let module_certificate = cells[0]
            .select(&a_selector)
            .next()
            .map(text_of)
            .unwrap_or_default();
        if module_certificate.is_empty() {
            continue;
        }
        rows.push(ResultRow {
            module_certificate,
            vendor: text_of(cells[1]),
            module_name: text_of(cells[2]),
            module_type: text_of(cells[3]),
            validation_date: text_of(cells[4]),
            certificate_url: certificate_link,
            ..Default::default()
        });
    }
    Ok((rows, message))
}

fn parse_esv_results_page(html_text: &str) -> Result<Vec<ResultRow>> {
    let html = Html::parse_document(html_text);
    let row_selector = selector("#searchResultsTable tbody tr")?;
    let td_selector = selector("td")?;
    let a_selector = selector("a")?;

    let mut rows = Vec::new();
    for row in html.select(&row_selector) {
        let cells: Vec<_> = row.select(&td_selector).collect();
        if cells.len() < 4 {
            continue;
        }
        let certificate_link = cells[2]
            .select(&a_selector)
            .next()
            .and_then(|a| a.value().attr("href"))
            .map(absolute_url)
            .unwrap_or_default();
        let module_certificate = cells[2]
            .select(&a_selector)
            .next()
            .map(text_of)
            .unwrap_or_default();
        if module_certificate.is_empty() {
            continue;
        }
        rows.push(ResultRow {
            module_certificate,
            vendor: text_of(cells[0]),
            module_name: text_of(cells[1]),
            validation_date: text_of(cells[3]),
            certificate_url: certificate_link,
            ..Default::default()
        });
    }
    Ok(rows)
}

fn status_listing_url(status: &str) -> (&'static str, Vec<(&'static str, &'static str)>) {
    if status == "Active" {
        (CMVP_SEARCH_ALL_URL, vec![])
    } else {
        (
            CMVP_SEARCH_URL,
            vec![
                ("SearchMode", "Advanced"),
                (
                    "CertificateStatus",
                    if status == "Historical" {
                        "Historical"
                    } else {
                        "Revoked"
                    },
                ),
            ],
        )
    }
}

fn parse_cached_certificate_html(path: &Path) -> Result<ResultRow> {
    let html_text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let html = Html::parse_document(&html_text);
    let h3_selector = selector("h3")?;
    let module_name_selector = selector("#module-name")?;
    let panel_selector = selector("div.panel.panel-default")?;
    let title_selector = selector("h4.panel-title")?;
    let body_selector = selector("div.panel-body")?;
    let link_selector = selector("a")?;
    let padrow_selector = selector("div.row.padrow")?;
    let col_selector = selector("div.col-md-3, div.col-md-9")?;
    let history_selector = selector("#validation-history-table tbody tr td.text-nowrap")?;

    let module_certificate = html
        .select(&h3_selector)
        .find_map(|node| {
            let text = text_of(node);
            text.strip_prefix("Certificate #")
                .map(|value| value.trim().to_string())
        })
        .unwrap_or_else(|| {
            path.file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned()
        });
    let module_name = html
        .select(&module_name_selector)
        .next()
        .map(text_of)
        .unwrap_or_default();
    let validation_date = html
        .select(&history_selector)
        .next()
        .map(text_of)
        .unwrap_or_default();

    let mut vendor = String::new();
    let mut module_type = String::new();
    let mut policy_url = String::new();
    for panel in html.select(&panel_selector) {
        let title = panel
            .select(&title_selector)
            .next()
            .map(text_of)
            .unwrap_or_default();
        if title == "Vendor" {
            vendor = panel
                .select(&body_selector)
                .next()
                .map(first_non_empty_text)
                .unwrap_or_default();
        } else if title == "Related Files" {
            policy_url = panel
                .select(&body_selector)
                .next()
                .and_then(|body| body.select(&link_selector).next())
                .and_then(|link| link.value().attr("href"))
                .map(absolute_url)
                .unwrap_or_default();
        }
    }

    for row in html.select(&padrow_selector) {
        let cols: Vec<_> = row.select(&col_selector).collect();
        if cols.len() < 2 {
            continue;
        }
        let label = text_of(cols[0]);
        if label == "Module Type" {
            module_type = text_of(cols[1]);
        }
    }

    Ok(ResultRow {
        module_certificate: module_certificate.clone(),
        vendor,
        module_name,
        module_type,
        validation_date,
        certificate_url: format!(
            "{BASE_URL}/projects/cryptographic-module-validation-program/certificate/{module_certificate}"
        ),
        policy_url,
        ..Default::default()
    })
}

fn parse_cached_esv_certificate_html(path: &Path) -> Result<ResultRow> {
    let fallback_certificate = path
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let html_text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    parse_esv_certificate_html(&html_text, &fallback_certificate)
}

fn parse_esv_certificate_html(html_text: &str, fallback_certificate: &str) -> Result<ResultRow> {
    let html = Html::parse_document(html_text);
    let h3_selector = selector("h3")?;
    let panel_selector = selector("div.panel.panel-default")?;
    let title_selector = selector("h4.panel-title")?;
    let body_selector = selector("div.panel-body")?;
    let link_selector = selector("a")?;
    let padrow_selector = selector("div.row.padrow")?;
    let col_selector = selector("div.col-md-3, div.col-md-9")?;
    let history_selector = selector("#validation-history-table tbody tr td.text-nowrap")?;

    let module_certificate = html
        .select(&h3_selector)
        .find_map(|node| {
            let text = text_of(node);
            text.strip_prefix("Entropy Certificate #")
                .map(|value| value.trim().to_string())
        })
        .unwrap_or_else(|| fallback_certificate.to_string());
    let validation_date = html
        .select(&history_selector)
        .next()
        .map(text_of)
        .unwrap_or_default();

    let mut vendor = String::new();
    let mut entropy_document_url = String::new();
    for panel in html.select(&panel_selector) {
        let title = panel
            .select(&title_selector)
            .next()
            .map(text_of)
            .unwrap_or_default();
        if title == "Vendor" {
            vendor = panel
                .select(&body_selector)
                .next()
                .map(first_non_empty_text)
                .unwrap_or_default();
        } else if title == "Related Files" {
            entropy_document_url = panel
                .select(&body_selector)
                .next()
                .and_then(|body| body.select(&link_selector).next())
                .and_then(|link| link.value().attr("href"))
                .map(absolute_url)
                .unwrap_or_default();
        }
    }

    let mut module_name = String::new();
    let mut esv_standard = String::new();
    let mut esv_description = String::new();
    let mut esv_noise_source = String::new();
    let mut esv_reuse_status = String::new();
    for row in html.select(&padrow_selector) {
        let cols: Vec<_> = row.select(&col_selector).collect();
        if cols.len() < 2 {
            continue;
        }
        let label = text_of(cols[0]);
        let value = text_of(cols[1]);
        match label.as_str() {
            "Implementation Name" => module_name = value,
            "Standard" => esv_standard = value,
            "Description" => esv_description = value,
            "Noise Source Classification" => esv_noise_source = value,
            "Reuse Status" => esv_reuse_status = value,
            _ => {}
        }
    }

    let certificate_number = module_certificate.trim_start_matches('E').to_string();
    Ok(ResultRow {
        module_certificate,
        vendor,
        module_name,
        validation_date,
        certificate_url: format!(
            "{BASE_URL}/projects/cryptographic-module-validation-program/entropy-validations/certificate/{certificate_number}"
        ),
        esv_standard,
        esv_description,
        esv_noise_source,
        esv_reuse_status,
        entropy_document_url,
        ..Default::default()
    })
}

fn fetch_status_catalog(
    client: &Client,
    cache_dir: &Path,
    status: &str,
    offline: bool,
) -> Result<Vec<ResultRow>> {
    if offline {
        let cert_dir = cache_dir.join("certificates");
        let mut rows = Vec::new();
        for entry in fs::read_dir(&cert_dir)
            .with_context(|| format!("failed to read {}", cert_dir.display()))?
        {
            let path = entry?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("html") {
                continue;
            }
            rows.push(parse_cached_certificate_html(&path)?);
        }
        rows.sort_by(|a, b| b.module_certificate.cmp(&a.module_certificate));
        return Ok(rows);
    }

    let (url, query) = status_listing_url(status);
    let html = fetch_text(client, url, &query)?;
    let (rows, _) = parse_results_page(&html)?;
    if rows.is_empty() && status != "Revoked" {
        bail!("could not parse any certificates from the {status} listing page");
    }
    Ok(rows)
}

fn fetch_esv_catalog(client: &Client, cache_dir: &Path, offline: bool) -> Result<Vec<ResultRow>> {
    if offline {
        let cert_dir = cache_dir.join("esv-certificates");
        let mut rows = Vec::new();
        for entry in fs::read_dir(&cert_dir)
            .with_context(|| format!("failed to read {}", cert_dir.display()))?
        {
            let path = entry?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("html") {
                continue;
            }
            rows.push(parse_cached_esv_certificate_html(&path)?);
        }
        rows.sort_by(|a, b| b.module_certificate.cmp(&a.module_certificate));
        return Ok(rows);
    }

    let mut rows = Vec::new();
    for page in 1.. {
        let page_value = page.to_string();
        let page_rows = parse_esv_results_page(&fetch_text(
            client,
            ESV_SEARCH_URL,
            &[("page", page_value.as_str())],
        )?)?;
        if page_rows.is_empty() {
            break;
        }
        rows.extend(page_rows);
    }
    if rows.is_empty() {
        bail!("could not parse any certificates from the ESV listing page");
    }
    rows.sort_by(|a, b| b.module_certificate.cmp(&a.module_certificate));
    Ok(dedupe_rows(rows))
}

fn classify_iid_claim(pdf_text: &str) -> Result<IidClaim> {
    let text = pdf_text.replace('\u{c}', "\n");
    let structured_track_re =
        Regex::new(r"(?is)\bEntropy\s+Estimation\s+Track\b.{0,120}?\b(Non[-\s]?IID|IID)\b")?;
    if let Some(captures) = structured_track_re.captures(&text) {
        let value = captures
            .get(1)
            .map(|capture| capture.as_str())
            .unwrap_or_default();
        return Ok(if value.to_ascii_lowercase().starts_with("non") {
            IidClaim::NonIid
        } else {
            IidClaim::Iid
        });
    }

    let narrative_track_re = Regex::new(
        r"(?is)\bThe\s+(Non[-\s]?IID|IID)\s+entropy\s+estimation\s+track\s+is\s+chosen\b",
    )?;
    if let Some(captures) = narrative_track_re.captures(&text) {
        let value = captures
            .get(1)
            .map(|capture| capture.as_str())
            .unwrap_or_default();
        return Ok(if value.to_ascii_lowercase().starts_with("non") {
            IidClaim::NonIid
        } else {
            IidClaim::Iid
        });
    }

    Ok(IidClaim::Unknown)
}

fn enrich_esv_certificate(
    client: &Client,
    cache_dir: &Path,
    row: &ResultRow,
    fresh: bool,
) -> Result<ResultRow> {
    let certificate_html = cache_esv_certificate_html(
        client,
        cache_dir,
        &row.certificate_url,
        &row.module_certificate,
        fresh,
    )?;
    let mut enriched = parse_esv_certificate_html(&certificate_html, &row.module_certificate)?;
    if !enriched.vendor.is_empty() {
        enriched.vendor = enriched.vendor.trim().to_string();
    } else {
        enriched.vendor = row.vendor.clone();
    }
    if enriched.module_name.is_empty() {
        enriched.module_name = row.module_name.clone();
    }
    if enriched.validation_date.is_empty() {
        enriched.validation_date = row.validation_date.clone();
    }
    if enriched
        .entropy_document_url
        .to_ascii_lowercase()
        .ends_with(".pdf")
    {
        let pdf_text = extract_cached_pdf_text(
            client,
            cache_dir,
            "entropy-documents",
            &enriched.entropy_document_url,
            fresh,
        )?;
        enriched.iid_claim = classify_iid_claim(&pdf_text)?;
    }
    Ok(enriched)
}

fn dedupe_rows(rows: Vec<ResultRow>) -> Vec<ResultRow> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();
    for row in rows {
        let key = (
            row.module_certificate.clone(),
            row.certificate_url.clone(),
            row.cavp_certificate.clone(),
            row.cavp_algorithm.clone(),
        );
        if seen.insert(key) {
            deduped.push(row);
        }
    }
    deduped
}

fn search_cmvp_form(
    client: &Client,
    term: &str,
    options: &HashMap<String, String>,
    statuses: &[String],
) -> Result<(String, Vec<ResultRow>, String)> {
    let (field_name, field_value) = normalize_cmvp_algorithm(term, options)?;
    let mut rows = Vec::new();
    let mut messages = Vec::new();
    for status in statuses {
        let query = vec![
            ("SearchMode", "Advanced"),
            ("CertificateStatus", status.as_str()),
            (field_name.as_str(), field_value.as_str()),
        ];
        let html = fetch_text(client, CMVP_SEARCH_URL, &query)?;
        let (mut page_rows, message) = parse_results_page(&html)?;
        rows.append(&mut page_rows);
        if !message.is_empty() {
            messages.push(message);
        } else {
            messages.push(format!("No response message returned for {status}."));
        }
    }
    Ok((field_value, dedupe_rows(rows), messages.join(" | ")))
}

fn document_scan_supported(cache_dir: &Path, subdir: &str) -> bool {
    cache_dir.join(subdir).exists() || Command::new("pdftotext").arg("-v").output().is_ok()
}

fn policy_scan_supported(cache_dir: &Path) -> bool {
    document_scan_supported(cache_dir, "security-policies")
}

fn find_policy_url(certificate_html: &str) -> Result<Option<String>> {
    let re = Regex::new(
        r#"(?i)href="(?P<href>/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/[^"]+\.pdf)""#,
    )?;
    Ok(re
        .captures(certificate_html)
        .and_then(|captures| captures.name("href"))
        .map(|value| absolute_url(value.as_str())))
}

fn extract_section_25(pdf_text: &str) -> Result<String> {
    let text = pdf_text.replace('\u{c}', "\n");
    let start_re = Regex::new(r"(?m)^2\.5 Algorithms\b")?;
    let end_re = Regex::new(r"(?m)^2\.6\b")?;
    let starts: Vec<_> = start_re.find_iter(&text).collect();
    let Some(last_start) = starts.last() else {
        return Ok(text);
    };
    let remainder = &text[last_start.start()..];
    let section = if let Some(end) = end_re.find(remainder) {
        &remainder[..end.start()]
    } else {
        remainder
    };
    let page_re = Regex::new(r"^Page \d+ of \d+$")?;
    let filtered = section
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|line| !line.is_empty())
        .filter(|line| {
            !matches!(
                line.as_str(),
                "Algorithm" | "CAVP" | "Cert" | "Properties" | "Reference"
            )
        })
        .filter(|line| !page_re.is_match(line))
        .collect::<Vec<_>>()
        .join("\n");
    Ok(filtered)
}

fn summarize_properties(snippet: &str, algorithm: &str, cavp_cert: &str) -> String {
    let mut condensed = snippet.split_whitespace().collect::<Vec<_>>().join(" ");
    if let Some(stripped) = condensed.strip_prefix(algorithm) {
        condensed = stripped.trim().to_string();
    }
    if !cavp_cert.is_empty() {
        if let Some(stripped) = condensed.strip_prefix(cavp_cert) {
            condensed = stripped.trim().to_string();
        }
    }
    condensed
        .trim_start_matches(|c: char| " -:;,.".contains(c))
        .chars()
        .take(220)
        .collect::<String>()
        .trim_end()
        .to_string()
}

fn derive_operation(query_term: &str, cavp_algorithm: &str) -> Result<String> {
    if cavp_algorithm.eq_ignore_ascii_case(query_term) {
        return Ok(cavp_algorithm.to_string());
    }
    let prefix = Regex::new(&format!(r"(?i)^{}[\s-]*", regex::escape(query_term)))?;
    let operation = prefix.replace(cavp_algorithm, "").trim().to_string();
    Ok(if operation.is_empty() {
        cavp_algorithm.to_string()
    } else {
        operation
    })
}

fn parse_section_matches(
    base_row: &ResultRow,
    section_text: &str,
    query_term: &str,
    candidate_algorithms: &[String],
) -> Result<Vec<ResultRow>> {
    let cert_re = Regex::new(r"\bA\d{3,6}\b")?;
    let mut matches = Vec::new();
    let mut seen = HashSet::new();
    for cavp_algorithm in candidate_algorithms {
        let pattern = compile_term_pattern(cavp_algorithm)?;
        for captures in pattern.captures_iter(section_text) {
            let Some(hit) = captures.get(2) else {
                continue;
            };
            let end = (hit.start() + 500).min(section_text.len());
            let snippet = &section_text[hit.start()..end];
            let cavp_cert = cert_re
                .find(snippet)
                .map(|value| value.as_str().to_string())
                .unwrap_or_default();
            let key = (
                base_row.module_certificate.clone(),
                cavp_algorithm.clone(),
                cavp_cert.clone(),
            );
            if !seen.insert(key) {
                continue;
            }
            matches.push(ResultRow {
                module_certificate: base_row.module_certificate.clone(),
                vendor: base_row.vendor.clone(),
                module_name: base_row.module_name.clone(),
                module_type: base_row.module_type.clone(),
                validation_date: base_row.validation_date.clone(),
                certificate_url: base_row.certificate_url.clone(),
                policy_url: base_row.policy_url.clone(),
                cavp_certificate: cavp_cert.clone(),
                cavp_algorithm: cavp_algorithm.clone(),
                operation: derive_operation(query_term, cavp_algorithm)?,
                properties: summarize_properties(snippet, cavp_algorithm, &cavp_cert),
                cavp_listed: true,
                ..Default::default()
            });
        }
    }
    Ok(matches)
}

fn parse_section_matches_offline(
    base_row: &ResultRow,
    section_text: &str,
    query_term: &str,
) -> Result<Vec<ResultRow>> {
    let term_pattern = compile_term_pattern(query_term)?;
    let cert_re = Regex::new(r"\bA\d{3,6}\b")?;
    let lines: Vec<&str> = section_text.lines().collect();
    let mut matches = Vec::new();
    let mut seen = HashSet::new();

    for (index, line) in lines.iter().enumerate() {
        if !term_pattern.is_match(line) {
            continue;
        }
        let cavp_algorithm = line.trim().to_string();
        let snippet = lines
            .iter()
            .skip(index)
            .take(10)
            .copied()
            .collect::<Vec<_>>()
            .join(" ");
        let cavp_cert = cert_re
            .find(&snippet)
            .map(|value| value.as_str().to_string())
            .unwrap_or_default();
        let key = (
            base_row.module_certificate.clone(),
            cavp_algorithm.clone(),
            cavp_cert.clone(),
        );
        if !seen.insert(key) {
            continue;
        }
        matches.push(ResultRow {
            module_certificate: base_row.module_certificate.clone(),
            vendor: base_row.vendor.clone(),
            module_name: base_row.module_name.clone(),
            module_type: base_row.module_type.clone(),
            validation_date: base_row.validation_date.clone(),
            certificate_url: base_row.certificate_url.clone(),
            policy_url: base_row.policy_url.clone(),
            cavp_certificate: cavp_cert.clone(),
            cavp_algorithm: cavp_algorithm.clone(),
            operation: derive_operation(query_term, &cavp_algorithm)?,
            properties: summarize_properties(&snippet, &cavp_algorithm, &cavp_cert),
            cavp_listed: !cavp_algorithm.is_empty(),
            ..Default::default()
        });
    }
    Ok(matches)
}

fn scan_policy_for_algorithms(
    client: &Client,
    cache_dir: &Path,
    base_row: &ResultRow,
    term_candidate_algorithms: &HashMap<String, Vec<String>>,
    fresh: bool,
) -> Result<HashMap<String, Vec<ResultRow>>> {
    let certificate_html = cache_certificate_html(
        client,
        cache_dir,
        &base_row.certificate_url,
        &base_row.module_certificate,
        fresh,
    )?;
    let resolved_policy_url = find_policy_url(&certificate_html)?
        .or_else(|| (!base_row.policy_url.is_empty()).then_some(base_row.policy_url.clone()));
    let Some(policy_url) = resolved_policy_url else {
        return Ok(term_candidate_algorithms
            .keys()
            .cloned()
            .map(|term| (term, Vec::new()))
            .collect());
    };

    let policy_text = extract_pdf_text(client, cache_dir, &policy_url, fresh)?;
    let section_text = extract_section_25(&policy_text)?;
    let mut row_with_policy = base_row.clone();
    row_with_policy.policy_url = policy_url;

    let mut results = HashMap::new();
    for (term, candidate_algorithms) in term_candidate_algorithms {
        let rows = if candidate_algorithms.is_empty() {
            parse_section_matches_offline(&row_with_policy, &section_text, term)?
        } else {
            parse_section_matches(&row_with_policy, &section_text, term, candidate_algorithms)?
        };
        results.insert(term.clone(), rows);
    }
    Ok(results)
}

fn scan_security_policies(
    client: &Client,
    cache_dir: &Path,
    status: &str,
    term_candidate_algorithms: &HashMap<String, Vec<String>>,
    fresh: bool,
    offline: bool,
) -> Result<(HashMap<String, Vec<ResultRow>>, HashMap<String, String>)> {
    if !policy_scan_supported(cache_dir) {
        let message =
            "pdftotext is not installed, so security-policy scanning is unavailable.".to_string();
        return Ok((
            term_candidate_algorithms
                .keys()
                .cloned()
                .map(|term| (term, Vec::new()))
                .collect(),
            term_candidate_algorithms
                .keys()
                .cloned()
                .map(|term| (term, message.clone()))
                .collect(),
        ));
    }

    fs::create_dir_all(cache_dir)?;
    let catalog = fetch_status_catalog(client, cache_dir, status, offline)?;
    let scanned: Vec<HashMap<String, Vec<ResultRow>>> = catalog
        .par_iter()
        .map(|row| {
            scan_policy_for_algorithms(client, cache_dir, row, term_candidate_algorithms, fresh)
        })
        .collect::<Result<Vec<_>>>()?;

    let mut matches: HashMap<String, Vec<ResultRow>> = term_candidate_algorithms
        .keys()
        .cloned()
        .map(|term| (term, Vec::new()))
        .collect();
    for result in scanned {
        for (term, rows) in result {
            matches.entry(term).or_default().extend(rows);
        }
    }

    let deduped: HashMap<String, Vec<ResultRow>> = matches
        .into_iter()
        .map(|(term, rows)| (term, dedupe_rows(rows)))
        .collect();
    let messages: HashMap<String, String> = deduped
        .iter()
        .map(|(term, rows)| {
            (
                term.clone(),
                format!(
                    "{status}: CMVP search page returned no matches; scanned {} module policies once, matched {} certified operation entries",
                    catalog.len(),
                    rows.len()
                ),
            )
        })
        .collect();
    Ok((deduped, messages))
}

fn search_products_for_terms(
    client: &Client,
    terms: &[String],
    cmvp_algorithm_options: &HashMap<String, String>,
    cavp_algorithms: &[String],
    status: &str,
    include_revoked: bool,
    policy_scan: bool,
    fresh: bool,
    cache_dir: &Path,
    offline: bool,
) -> Result<Vec<SearchOutcome>> {
    let mut statuses = vec![status.to_string()];
    if include_revoked && status != "Revoked" {
        statuses.push("Revoked".to_string());
    }

    let mut results_by_term: HashMap<String, SearchOutcome> = HashMap::new();
    let mut fallback_candidates: HashMap<String, Vec<String>> = HashMap::new();

    for term in terms {
        let (canonical_query, rows, results_message) = if offline {
            (
                term.clone(),
                Vec::new(),
                "Offline mode: skipping live CMVP search and using cached data only.".to_string(),
            )
        } else {
            search_cmvp_form(client, term, cmvp_algorithm_options, &statuses)?
        };
        results_by_term.insert(
            term.clone(),
            SearchOutcome {
                query: term.clone(),
                canonical_query,
                results_message,
                rows,
                kind: OutputKind::Cmvp,
            },
        );
        if policy_scan
            && results_by_term
                .get(term)
                .map(|outcome| outcome.rows.is_empty())
                .unwrap_or(false)
        {
            let candidates = if offline {
                Vec::new()
            } else {
                resolve_cavp_algorithms(term, cavp_algorithms)
            };
            if offline || !candidates.is_empty() {
                fallback_candidates.insert(term.clone(), candidates);
            }
        }
    }

    if !fallback_candidates.is_empty() {
        let mut rows_by_term: HashMap<String, Vec<ResultRow>> = fallback_candidates
            .keys()
            .cloned()
            .map(|term| (term, Vec::new()))
            .collect();
        let mut messages_by_term: HashMap<String, Vec<String>> = fallback_candidates
            .keys()
            .cloned()
            .map(|term| (term, Vec::new()))
            .collect();

        for current_status in &statuses {
            let (status_rows, status_messages) = scan_security_policies(
                client,
                cache_dir,
                current_status,
                &fallback_candidates,
                fresh,
                offline,
            )?;
            for term in fallback_candidates.keys() {
                if let Some(rows) = status_rows.get(term) {
                    rows_by_term
                        .entry(term.clone())
                        .or_default()
                        .extend(rows.clone());
                }
                if let Some(message) = status_messages.get(term) {
                    messages_by_term
                        .entry(term.clone())
                        .or_default()
                        .push(message.clone());
                }
            }
        }

        for term in fallback_candidates.keys() {
            if let Some(outcome) = results_by_term.get_mut(term) {
                outcome.rows = dedupe_rows(rows_by_term.remove(term).unwrap_or_default());
                outcome.results_message = messages_by_term
                    .remove(term)
                    .unwrap_or_default()
                    .join(" | ");
            }
        }
    }

    Ok(terms
        .iter()
        .filter_map(|term| results_by_term.remove(term))
        .collect())
}

fn render_table(outcome: &SearchOutcome) {
    println!("# {}", outcome.query);
    println!("{}", outcome.results_message);
    println!("Results: {}", outcome.rows.len());
    if outcome.rows.is_empty() {
        println!();
        return;
    }

    let header: Vec<&str>;
    let rows: Vec<Vec<String>>;
    match outcome.kind {
        OutputKind::Cmvp => {
            if outcome.canonical_query != outcome.query {
                println!("Matched CMVP field value: {}", outcome.canonical_query);
            }
            let has_cavp_details = outcome
                .rows
                .iter()
                .any(|row| !row.cavp_algorithm.is_empty());
            if has_cavp_details {
                header = vec![
                    "Module Cert",
                    "Vendor",
                    "Module Name",
                    "CAVP Cert",
                    "CAVP Algorithm",
                    "Operation",
                ];
                rows = outcome
                    .rows
                    .iter()
                    .map(|row| {
                        vec![
                            row.module_certificate.clone(),
                            row.vendor.clone(),
                            row.module_name.clone(),
                            row.cavp_certificate.clone(),
                            row.cavp_algorithm.clone(),
                            row.operation.clone(),
                        ]
                    })
                    .collect();
            } else {
                header = vec!["Certificate", "Vendor", "Module Name", "Type", "Validated"];
                rows = outcome
                    .rows
                    .iter()
                    .map(|row| {
                        vec![
                            row.module_certificate.clone(),
                            row.vendor.clone(),
                            row.module_name.clone(),
                            row.module_type.clone(),
                            row.validation_date.clone(),
                        ]
                    })
                    .collect();
            }
        }
        OutputKind::Esv => {
            println!("IID filter: {}", outcome.canonical_query);
            header = vec![
                "Certificate",
                "Vendor",
                "Implementation",
                "IID Claim",
                "Noise Source",
                "Validated",
            ];
            rows = outcome
                .rows
                .iter()
                .map(|row| {
                    vec![
                        row.module_certificate.clone(),
                        row.vendor.clone(),
                        row.module_name.clone(),
                        row.iid_claim.as_str().to_string(),
                        row.esv_noise_source.clone(),
                        row.validation_date.clone(),
                    ]
                })
                .collect();
        }
    }

    let mut widths: Vec<usize> = header.iter().map(|value| value.len()).collect();
    for row in &rows {
        for (index, value) in row.iter().enumerate() {
            widths[index] = widths[index].max(value.len());
        }
    }

    println!(
        "{}",
        format_row(
            &header
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>(),
            &widths
        )
    );
    println!(
        "{}",
        widths
            .iter()
            .map(|width| "-".repeat(*width))
            .collect::<Vec<_>>()
            .join("-+-")
    );
    for row in rows {
        println!("{}", format_row(&row, &widths));
    }
    println!();
}

fn format_row(row: &[String], widths: &[usize]) -> String {
    row.iter()
        .enumerate()
        .map(|(index, value)| format!("{value:<width$}", width = widths[index]))
        .collect::<Vec<_>>()
        .join(" | ")
}

fn write_csv(path: &Path, outcomes: &[SearchOutcome]) -> Result<()> {
    let mut writer = csv::Writer::from_path(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    writer.write_record([
        "kind",
        "query",
        "canonical_query",
        "module_certificate",
        "vendor",
        "module_name",
        "module_type",
        "validation_date",
        "certificate_url",
        "policy_url",
        "cavp_certificate",
        "cavp_algorithm",
        "operation",
        "properties",
        "cavp_listed",
        "esv_standard",
        "esv_description",
        "esv_noise_source",
        "esv_reuse_status",
        "entropy_document_url",
        "iid_claim",
    ])?;
    for outcome in outcomes {
        for row in &outcome.rows {
            writer.write_record([
                match outcome.kind {
                    OutputKind::Cmvp => "cmvp",
                    OutputKind::Esv => "esv",
                },
                outcome.query.as_str(),
                outcome.canonical_query.as_str(),
                row.module_certificate.as_str(),
                row.vendor.as_str(),
                row.module_name.as_str(),
                row.module_type.as_str(),
                row.validation_date.as_str(),
                row.certificate_url.as_str(),
                row.policy_url.as_str(),
                row.cavp_certificate.as_str(),
                row.cavp_algorithm.as_str(),
                row.operation.as_str(),
                row.properties.as_str(),
                if row.cavp_listed { "true" } else { "false" },
                row.esv_standard.as_str(),
                row.esv_description.as_str(),
                row.esv_noise_source.as_str(),
                row.esv_reuse_status.as_str(),
                row.entropy_document_url.as_str(),
                row.iid_claim.as_str(),
            ])?;
        }
    }
    writer.flush()?;
    Ok(())
}

fn write_json(path: &Path, outcomes: &[SearchOutcome]) -> Result<()> {
    let payload: Vec<JsonOutput> = outcomes
        .iter()
        .map(|outcome| JsonOutput {
            query: outcome.query.clone(),
            canonical_query: outcome.canonical_query.clone(),
            results_message: outcome.results_message.clone(),
            results: outcome.rows.clone(),
        })
        .collect();
    fs::write(path, serde_json::to_vec_pretty(&payload)?)
        .with_context(|| format!("failed to write {}", path.display()))
}
