#![forbid(unsafe_code)]

mod clipboard;
mod config;
mod security;

use anyhow::{bail, Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use config::{config_path, Config, ConfigAlgorithm, ParameterOverrides};
use destiny_password_cli::{
    canonicalize_v3_email, canonicalize_v3_host, generate, validate_parameters, Algorithm,
    Parameters, V3_ARGON2_LANES, V3_ARGON2_MEMORY_KIB, V3_ARGON2_PASSES,
};
use std::io::{self, IsTerminal, Read};
use zeroize::{Zeroize, Zeroizing};

#[derive(Parser)]
#[command(
    name = "destiny",
    version,
    about = "Local deterministic passwords with frozen One Shall Pass compatibility",
    long_about = "Generate site-specific passwords entirely on this machine. V3 is memory-hard by default; One Shall Pass v2/v1 remain available through --legacy. With a saved email, `destiny <host>` securely prompts for the master password and copies the result to the clipboard."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// HOST (with saved/--email) or EMAIL HOST; the password is prompted securely
    #[arg(value_name = "INPUT", num_args = 0..=2)]
    inputs: Vec<String>,

    /// Use this email instead of the saved email
    #[arg(long, value_name = "EMAIL")]
    email: Option<String>,

    /// Read the master password from standard input instead of prompting
    #[arg(long)]
    password_stdin: bool,

    /// Print the generated password to stdout instead of copying it
    #[arg(long)]
    print: bool,

    /// Clear the clipboard after N seconds if it still contains this password (0 disables)
    #[arg(long, value_name = "SECONDS", value_parser = parse_clear_after)]
    clear_after: Option<u32>,

    /// Show the resolved non-secret inputs and parameters on stderr
    #[arg(long = "params", visible_alias = "show-params")]
    show_params: bool,

    #[command(flatten)]
    parameters: ParameterFlags,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Save non-secret defaults and host profiles
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    #[command(name = "__clipboard-service", hide = true)]
    ClipboardService {
        #[arg(value_parser = parse_clear_after)]
        clear_after_seconds: u32,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Save the default email address
    Email { email: String },
    /// Remove the saved default email address
    ClearEmail,
    /// Add or update a host profile (NAME can itself be the host)
    Host {
        name: String,
        /// Actual host value, when NAME is an alias such as "work"
        #[arg(long, value_name = "HOST")]
        value: Option<String>,
        #[command(flatten)]
        parameters: ParameterFlags,
    },
    /// Remove a saved host profile
    RemoveHost { name: String },
    /// Update global parameter defaults
    Defaults {
        #[command(flatten)]
        parameters: ParameterFlags,
    },
    /// Show saved non-secret configuration
    List,
    /// Print the config file path
    Path,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum AlgorithmArg {
    V3,
    V2,
    V1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum LegacyAlgorithmArg {
    V2,
    V1,
}

#[derive(Args, Clone, Copy, Debug, Default)]
struct ParameterFlags {
    /// Legacy work-factor exponent (v2 PBKDF2 rounds; v1 search factor = 2^BITS)
    #[arg(long = "bits", value_name = "BITS", value_parser = parse_security_bits)]
    security_bits: Option<u8>,

    /// Password generation number; increment to rotate a host password
    #[arg(short = 'g', long, value_name = "N", value_parser = parse_generation)]
    generation: Option<u32>,

    /// Generated length: 12..16 for v3, or 8..16 for legacy versions
    #[arg(short = 'l', long, value_name = "N", value_parser = parse_length)]
    length: Option<u8>,

    /// Number of symbols, from 0 through 3
    #[arg(short = 's', long, value_name = "N", value_parser = parse_symbols)]
    symbols: Option<u8>,

    /// Algorithm version (v3 is the modern default)
    #[arg(long, value_enum, value_name = "VERSION")]
    algorithm: Option<AlgorithmArg>,

    /// Use a frozen One Shall Pass version: --legacy v2 or --legacy v1
    #[arg(long, value_enum, value_name = "VERSION", conflicts_with = "algorithm")]
    legacy: Option<LegacyAlgorithmArg>,
}

impl ParameterFlags {
    fn overrides(self) -> ParameterOverrides {
        let algorithm = self
            .algorithm
            .map(config_algorithm)
            .or_else(|| self.legacy.map(legacy_config_algorithm));
        ParameterOverrides {
            algorithm,
            security_bits: self.security_bits,
            generation: self.generation,
            length: self.length,
            symbols: self.symbols,
        }
    }
}

fn main() {
    if let Err(error) = security::harden_process().and_then(|()| run()) {
        eprintln!("error: {error:#}");
        std::process::exit(2);
    }
}

fn run() -> Result<()> {
    let mut cli = Cli::parse();

    if let Some(command) = cli.command {
        if let Command::ClipboardService {
            clear_after_seconds,
        } = &command
        {
            if !cli.inputs.is_empty()
                || cli.email.is_some()
                || cli.password_stdin
                || cli.print
                || cli.clear_after.is_some()
                || cli.show_params
                || !cli.parameters.overrides().is_empty()
            {
                bail!("invalid private clipboard-service invocation");
            }
            if io::stdin().is_terminal() {
                bail!("private clipboard service requires piped input");
            }
            return clipboard::run_service(*clear_after_seconds);
        }

        if !cli.inputs.is_empty()
            || cli.email.is_some()
            || cli.password_stdin
            || cli.print
            || cli.clear_after.is_some()
            || cli.show_params
            || !cli.parameters.overrides().is_empty()
        {
            bail!("generation arguments cannot be combined with a config command");
        }
        return run_config(command, &config_path()?);
    }

    if cli.inputs.is_empty() {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    }

    if cli.print && cli.clear_after.is_some() {
        bail!("--clear-after applies only to clipboard output and cannot be combined with --print");
    }

    let path = config_path()?;
    let config = Config::load(&path)?;
    let (email, host_input) = resolve_inputs(&mut cli.inputs, cli.email, config.email.as_deref())?;

    let (host, profile_parameters) = config.resolve_host(&host_input);
    let mut overrides = config.defaults;
    if let Some(profile_parameters) = profile_parameters {
        overrides = overrides.overlay(*profile_parameters);
    }
    overrides = overrides.overlay(cli.parameters.overrides());
    let parameters = overrides.resolve();
    if parameters.algorithm == Algorithm::V3 && cli.parameters.security_bits.is_some() {
        bail!("--bits applies only to --legacy v2 or --legacy v1; v3's Argon2id cost is fixed");
    }
    validate_parameters(parameters)?;

    let (email, host) = if parameters.algorithm == Algorithm::V3 {
        (canonicalize_v3_email(&email)?, canonicalize_v3_host(&host)?)
    } else {
        (email, host)
    };

    let passphrase = if cli.password_stdin {
        if io::stdin().is_terminal() {
            bail!("--password-stdin requires piped or redirected input; omit it to use the hidden terminal prompt");
        }
        Zeroizing::new(read_password_from_stdin()?)
    } else {
        if !io::stdin().is_terminal() {
            bail!("stdin is not a terminal; pass --password-stdin to read the master password from it");
        }
        Zeroizing::new(
            rpassword::prompt_password("Master password: ")
                .context("could not read the master password")?,
        )
    };

    if cli.show_params {
        eprintln!("email:      {email}");
        eprintln!("host:       {host}");
        eprintln!("algorithm:  {}", algorithm_name(parameters.algorithm));
        match parameters.algorithm {
            Algorithm::V3 => eprintln!(
                "kdf:        Argon2id v1.3 ({} MiB, {} passes, {} lanes)",
                V3_ARGON2_MEMORY_KIB / 1024,
                V3_ARGON2_PASSES,
                V3_ARGON2_LANES
            ),
            Algorithm::V2 => eprintln!(
                "bits:       {} ({} PBKDF2 iterations)",
                parameters.security_bits,
                1u32 << parameters.security_bits
            ),
            Algorithm::LegacyV1 => eprintln!(
                "bits:       {} (legacy search factor {})",
                parameters.security_bits,
                1u32 << parameters.security_bits
            ),
        }
        eprintln!("generation: {}", parameters.generation);
        eprintln!("length:     {}", parameters.length);
        eprintln!("symbols:    {}", parameters.symbols);
    }

    let password = Zeroizing::new(generate(&email, &passphrase, &host, parameters)?);
    if cli.print {
        println!("{}", password.as_str());
    } else {
        let clear_after = cli.clear_after.unwrap_or(45);
        clipboard::copy(&password, clear_after)
            .context("could not copy password; rerun with --print only if displaying it is safe")?;
        if clear_after == 0 {
            eprintln!("Password copied to the system clipboard for {host}; automatic clearing is disabled.");
        } else {
            eprintln!(
                "Password copied to the system clipboard for {host}; it will clear in {clear_after}s if unchanged."
            );
        }
    }
    Ok(())
}

fn resolve_inputs(
    inputs: &mut Vec<String>,
    email_flag: Option<String>,
    saved_email: Option<&str>,
) -> Result<(String, String)> {
    let taken = std::mem::take(inputs);
    match taken.len() {
        1 => {
            let email = email_flag
                .or_else(|| saved_email.map(str::to_owned))
                .context(
                "no email supplied or saved; run `destiny config email <EMAIL>` or pass --email",
            )?;
            let host = taken.into_iter().next().expect("one positional input");
            Ok((email, host))
        }
        2 => {
            if email_flag.is_some() {
                bail!("with --email, pass only HOST as the positional argument");
            }
            let mut values = taken.into_iter();
            let email = values.next().expect("first of two positional inputs");
            let host = values.next().expect("second of two positional inputs");
            Ok((email, host))
        }
        _ => bail!("expected HOST or EMAIL HOST"),
    }
}

fn read_password_from_stdin() -> Result<String> {
    let mut value = Zeroizing::new(String::new());
    io::stdin()
        .read_to_string(&mut value)
        .context("could not read the master password from stdin")?;
    while value.ends_with('\n') || value.ends_with('\r') {
        value.pop();
    }
    if value.contains('\n') || value.contains('\r') {
        value.zeroize();
        bail!("--password-stdin accepts exactly one line");
    }
    Ok(value.as_str().to_owned())
}

fn run_config(command: Command, path: &std::path::Path) -> Result<()> {
    let command = match command {
        Command::Config { command } => command,
        Command::ClipboardService { .. } => unreachable!("handled before config dispatch"),
    };

    if matches!(command, ConfigCommand::Path) {
        println!("{}", path.display());
        return Ok(());
    }

    let mut config = Config::load(path)?;
    match command {
        ConfigCommand::Email { email } => {
            if email.trim().is_empty() {
                bail!("email must not be empty");
            }
            config.email = Some(email);
            config.save(path)?;
            eprintln!("Saved the default email in {}.", path.display());
        }
        ConfigCommand::ClearEmail => {
            config.email = None;
            config.save(path)?;
            eprintln!("Removed the default email from {}.", path.display());
        }
        ConfigCommand::Host {
            mut name,
            value,
            parameters,
        } => {
            name = name.trim().to_owned();
            if name.is_empty() {
                bail!("profile name must not be empty");
            }
            if value.as_ref().is_some_and(|value| value.trim().is_empty()) {
                bail!("host value must not be empty");
            }
            let incoming = parameters.overrides();
            let storage_name = config
                .matching_host_key(&name)
                .map(str::to_owned)
                .unwrap_or_else(|| name.clone());
            let profile = config.hosts.entry(storage_name).or_default();
            let effective = config
                .defaults
                .overlay(profile.parameters)
                .overlay(incoming)
                .resolve();
            if incoming.security_bits.is_some() && effective.algorithm == Algorithm::V3 {
                bail!("--bits requires --legacy v2 or --legacy v1 for a v3 profile");
            }
            if let Some(value) = value {
                profile.host = Some(value);
            }
            profile.parameters = profile.parameters.overlay(incoming);
            config.save(path)?;
            eprintln!("Saved host profile `{name}` in {}.", path.display());
        }
        ConfigCommand::RemoveHost { name } => {
            let stored_name = config.matching_host_key(&name).map(str::to_owned);
            if stored_name
                .as_deref()
                .and_then(|stored_name| config.hosts.remove(stored_name))
                .is_none()
            {
                bail!("no host profile named `{name}`");
            }
            config.save(path)?;
            eprintln!("Removed host profile `{name}` from {}.", path.display());
        }
        ConfigCommand::Defaults { parameters } => {
            let incoming = parameters.overrides();
            if incoming.is_empty() {
                bail!("supply at least one parameter to update");
            }
            let effective = config.defaults.overlay(incoming).resolve();
            if incoming.security_bits.is_some() && effective.algorithm == Algorithm::V3 {
                bail!("--bits requires --legacy v2 or --legacy v1 for v3 defaults");
            }
            config.defaults = config.defaults.overlay(incoming);
            config.save(path)?;
            eprintln!("Updated defaults in {}.", path.display());
        }
        ConfigCommand::List => print_config(&config, path),
        ConfigCommand::Path => unreachable!("handled before loading config"),
    }
    Ok(())
}

fn print_config(config: &Config, path: &std::path::Path) {
    println!("config: {}", path.display());
    println!("email:  {}", config.email.as_deref().unwrap_or("<not set>"));
    let defaults = config.defaults.resolve();
    print_parameter_summary("defaults", defaults);
    if config.hosts.is_empty() {
        println!("hosts:   <none>");
    } else {
        println!("hosts:");
        for (name, profile) in &config.hosts {
            let parameters = config.defaults.overlay(profile.parameters).resolve();
            let bits = match parameters.algorithm {
                Algorithm::V3 => String::new(),
                Algorithm::V2 | Algorithm::LegacyV1 => {
                    format!(" bits={}", parameters.security_bits)
                }
            };
            println!(
                "  {name} -> {}  algorithm={}{} generation={} length={} symbols={}",
                profile.host.as_deref().unwrap_or(name),
                algorithm_name(parameters.algorithm),
                bits,
                parameters.generation,
                parameters.length,
                parameters.symbols
            );
        }
    }
}

fn print_parameter_summary(label: &str, parameters: Parameters) {
    let bits = match parameters.algorithm {
        Algorithm::V3 => String::new(),
        Algorithm::V2 | Algorithm::LegacyV1 => {
            format!(" bits={}", parameters.security_bits)
        }
    };
    println!(
        "{label}: algorithm={}{} generation={} length={} symbols={}",
        algorithm_name(parameters.algorithm),
        bits,
        parameters.generation,
        parameters.length,
        parameters.symbols
    );
}

fn algorithm_name(algorithm: Algorithm) -> &'static str {
    match algorithm {
        Algorithm::V3 => "v3",
        Algorithm::V2 => "v2 (legacy)",
        Algorithm::LegacyV1 => "v1 (legacy)",
    }
}

fn config_algorithm(algorithm: AlgorithmArg) -> ConfigAlgorithm {
    match algorithm {
        AlgorithmArg::V3 => ConfigAlgorithm::V3,
        AlgorithmArg::V2 => ConfigAlgorithm::V2,
        AlgorithmArg::V1 => ConfigAlgorithm::V1,
    }
}

fn legacy_config_algorithm(algorithm: LegacyAlgorithmArg) -> ConfigAlgorithm {
    match algorithm {
        LegacyAlgorithmArg::V2 => ConfigAlgorithm::V2,
        LegacyAlgorithmArg::V1 => ConfigAlgorithm::V1,
    }
}

fn parse_security_bits(value: &str) -> std::result::Result<u8, String> {
    parse_u8_in_range(value, 1, 16, "bits")
}

fn parse_length(value: &str) -> std::result::Result<u8, String> {
    parse_u8_in_range(value, 8, 16, "length")
}

fn parse_symbols(value: &str) -> std::result::Result<u8, String> {
    parse_u8_in_range(value, 0, 3, "symbols")
}

fn parse_u8_in_range(
    value: &str,
    minimum: u8,
    maximum: u8,
    name: &str,
) -> std::result::Result<u8, String> {
    let parsed = value
        .parse::<u8>()
        .map_err(|_| format!("{name} must be an integer from {minimum} through {maximum}"))?;
    if (minimum..=maximum).contains(&parsed) {
        Ok(parsed)
    } else {
        Err(format!(
            "{name} must be from {minimum} through {maximum}, got {parsed}"
        ))
    }
}

fn parse_generation(value: &str) -> std::result::Result<u32, String> {
    let parsed = value
        .parse::<u32>()
        .map_err(|_| "generation must be a positive integer".to_owned())?;
    if parsed == 0 {
        Err("generation must be at least 1".to_owned())
    } else {
        Ok(parsed)
    }
}

fn parse_clear_after(value: &str) -> std::result::Result<u32, String> {
    let parsed = value
        .parse::<u32>()
        .map_err(|_| "clear-after must be an integer from 0 through 3600".to_owned())?;
    if parsed <= 3600 {
        Ok(parsed)
    } else {
        Err("clear-after must be from 0 through 3600 seconds".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_host_or_email_and_host_only() {
        assert!(Cli::try_parse_from(["destiny", "github.com"]).is_ok());
        assert!(Cli::try_parse_from(["destiny", "me@example.com", "github.com"]).is_ok());
    }

    #[test]
    fn rejects_a_positional_master_password() {
        assert!(Cli::try_parse_from([
            "destiny",
            "me@example.com",
            "master-password",
            "github.com"
        ])
        .is_err());
    }

    #[test]
    fn legacy_versions_are_explicit() {
        assert!(Cli::try_parse_from(["destiny", "github.com", "--legacy", "v2"]).is_ok());
        assert!(Cli::try_parse_from(["destiny", "github.com", "--legacy", "v1"]).is_ok());
        assert!(Cli::try_parse_from(["destiny", "github.com", "--legacy"]).is_err());
        assert!(Cli::try_parse_from([
            "destiny",
            "github.com",
            "--legacy",
            "v2",
            "--algorithm",
            "v3"
        ])
        .is_err());
    }

    #[test]
    fn clipboard_timeout_is_bounded() {
        assert!(Cli::try_parse_from(["destiny", "github.com", "--clear-after", "3600"]).is_ok());
        assert!(Cli::try_parse_from(["destiny", "github.com", "--clear-after", "3601"]).is_err());
    }
}
