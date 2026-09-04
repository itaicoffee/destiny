use anyhow::{bail, Context, Result};
use destiny_password_cli::{
    canonicalize_v3_email, canonicalize_v3_host, validate_parameters, Algorithm, Parameters,
};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::Write,
    path::{Path, PathBuf},
};
use unicode_normalization::UnicodeNormalization;

const CONFIG_VERSION: u8 = 2;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub version: u8,
    pub email: Option<String>,
    pub defaults: ParameterOverrides,
    pub hosts: BTreeMap<String, HostProfile>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct HostProfile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    pub parameters: ParameterOverrides,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfigAlgorithm {
    V3,
    V2,
    V1,
}

impl From<ConfigAlgorithm> for Algorithm {
    fn from(value: ConfigAlgorithm) -> Self {
        match value {
            ConfigAlgorithm::V3 => Self::V3,
            ConfigAlgorithm::V2 => Self::V2,
            ConfigAlgorithm::V1 => Self::LegacyV1,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ParameterOverrides {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<ConfigAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_bits: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbols: Option<u8>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        match fs::symlink_metadata(path) {
            Ok(_) => verify_secure_config_path(path)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Self::new()),
            Err(error) => {
                return Err(error).with_context(|| format!("could not inspect {}", path.display()));
            }
        }
        let contents = fs::read_to_string(path)
            .with_context(|| format!("could not read {}", path.display()))?;

        #[derive(Deserialize)]
        struct VersionProbe {
            #[serde(default)]
            version: u8,
        }

        let version = toml::from_str::<VersionProbe>(&contents)
            .with_context(|| format!("invalid config file {}", path.display()))?
            .version;
        let config = match version {
            0 | 1 => ConfigV1::parse_and_migrate(&contents, path)?,
            CONFIG_VERSION => toml::from_str::<Self>(&contents)
                .with_context(|| format!("invalid config file {}", path.display()))?,
            unsupported => bail!(
                "unsupported config version {unsupported} in {} (this build supports version {CONFIG_VERSION})",
                path.display()
            ),
        };
        config.validate()?;
        Ok(config)
    }

    pub fn new() -> Self {
        Self {
            version: CONFIG_VERSION,
            ..Self::default()
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let parent = path
            .parent()
            .context("config path has no parent directory")?;
        let created_parent = !parent.exists();
        fs::create_dir_all(parent)
            .with_context(|| format!("could not create {}", parent.display()))?;
        prepare_directory(parent, created_parent)?;
        reject_symlink(path)?;

        let serialized = toml::to_string_pretty(self).context("could not serialize config")?;
        let mut temporary = tempfile::Builder::new()
            .prefix(".config.")
            .tempfile_in(parent)
            .with_context(|| {
                format!("could not create a temporary file in {}", parent.display())
            })?;
        restrict_file(temporary.path())?;
        temporary
            .write_all(serialized.as_bytes())
            .context("could not write temporary config")?;
        temporary
            .as_file_mut()
            .sync_all()
            .context("could not sync temporary config")?;
        temporary
            .persist(path)
            .map_err(|error| error.error)
            .with_context(|| format!("could not replace {}", path.display()))?;
        restrict_file(path)?;
        sync_directory(parent)?;
        Ok(())
    }

    pub fn resolve_host(&self, input: &str) -> (String, Option<&ParameterOverrides>) {
        let matched = self.matching_host_key(input).and_then(|name| {
            self.hosts
                .get_key_value(name)
                .map(|(stored_name, profile)| (stored_name.as_str(), profile))
        });

        match matched {
            Some((name, profile)) => (
                profile.host.clone().unwrap_or_else(|| name.to_owned()),
                Some(&profile.parameters),
            ),
            None => (input.to_owned(), None),
        }
    }

    pub fn matching_host_key(&self, input: &str) -> Option<&str> {
        let canonical = canonical_profile_name(input);
        self.hosts
            .keys()
            .find(|name| canonical_profile_name(name) == canonical)
            .map(String::as_str)
    }

    fn validate(&self) -> Result<()> {
        if self.version != CONFIG_VERSION {
            bail!(
                "config must use version {CONFIG_VERSION}, got {}",
                self.version
            );
        }
        if let Some(email) = &self.email {
            if email.trim().is_empty() {
                bail!("saved email must not be empty");
            }
        }

        let mut aliases = BTreeSet::new();
        let mut uses_v3 = self.defaults.resolve().algorithm == Algorithm::V3;
        for (name, profile) in &self.hosts {
            let canonical_name = canonical_profile_name(name);
            if canonical_name.is_empty() || name.trim() != name {
                bail!("host profile names must be non-empty and have no surrounding whitespace");
            }
            if !aliases.insert(canonical_name) {
                bail!("host profile names must be unique ignoring case and Unicode form");
            }
            if profile
                .host
                .as_ref()
                .is_some_and(|host| host.trim().is_empty())
            {
                bail!("host value for profile `{name}` must not be empty");
            }

            let merged = self.defaults.overlay(profile.parameters);
            let parameters = merged.resolve();
            uses_v3 |= parameters.algorithm == Algorithm::V3;
            validate_parameters(parameters)
                .with_context(|| format!("invalid parameters for host profile `{name}`"))?;
            if parameters.algorithm == Algorithm::V3 {
                canonicalize_v3_host(profile.host.as_deref().unwrap_or(name))
                    .with_context(|| format!("invalid v3 host profile `{name}`"))?;
            }
        }

        let defaults = self.defaults.resolve();
        validate_parameters(defaults).context("invalid global defaults")?;
        if uses_v3 {
            if let Some(email) = &self.email {
                canonicalize_v3_email(email).context("invalid saved email for v3")?;
            }
        }
        Ok(())
    }
}

impl ParameterOverrides {
    pub fn resolve(self) -> Parameters {
        let algorithm = self.algorithm.map(Algorithm::from).unwrap_or(Algorithm::V3);
        let mut parameters = Parameters::defaults_for(algorithm);
        if let Some(value) = self.security_bits {
            parameters.security_bits = value;
        }
        if let Some(value) = self.generation {
            parameters.generation = value;
        }
        if let Some(value) = self.length {
            parameters.length = value;
        }
        if let Some(value) = self.symbols {
            parameters.symbols = value;
        }
        parameters
    }

    pub fn overlay(self, higher_priority: Self) -> Self {
        Self {
            algorithm: higher_priority.algorithm.or(self.algorithm),
            security_bits: higher_priority.security_bits.or(self.security_bits),
            generation: higher_priority.generation.or(self.generation),
            length: higher_priority.length.or(self.length),
            symbols: higher_priority.symbols.or(self.symbols),
        }
    }

    pub fn is_empty(self) -> bool {
        self.algorithm.is_none()
            && self.security_bits.is_none()
            && self.generation.is_none()
            && self.length.is_none()
            && self.symbols.is_none()
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ConfigV1 {
    version: u8,
    email: Option<String>,
    defaults: ParameterOverridesV1,
    hosts: BTreeMap<String, HostProfileV1>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct HostProfileV1 {
    host: Option<String>,
    parameters: ParameterOverridesV1,
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ParameterOverridesV1 {
    security_bits: Option<u8>,
    generation: Option<u32>,
    length: Option<u8>,
    symbols: Option<u8>,
    legacy: Option<bool>,
}

impl ConfigV1 {
    fn parse_and_migrate(contents: &str, path: &Path) -> Result<Config> {
        let old: Self = toml::from_str(contents)
            .with_context(|| format!("invalid version-1 config file {}", path.display()))?;
        if old.version > 1 {
            bail!("not a version-1 config");
        }

        // Version 1's implicit default was v2. Record it explicitly so merely
        // upgrading Destiny can never rotate already-enrolled passwords.
        let mut defaults = old.defaults.migrate();
        defaults.algorithm = Some(match old.defaults.legacy {
            Some(true) => ConfigAlgorithm::V1,
            Some(false) | None => ConfigAlgorithm::V2,
        });
        let hosts = old
            .hosts
            .into_iter()
            .map(|(name, profile)| {
                (
                    name,
                    HostProfile {
                        host: profile.host,
                        parameters: profile.parameters.migrate(),
                    },
                )
            })
            .collect();
        Ok(Config {
            version: CONFIG_VERSION,
            email: old.email,
            defaults,
            hosts,
        })
    }
}

impl ParameterOverridesV1 {
    fn migrate(self) -> ParameterOverrides {
        ParameterOverrides {
            algorithm: self.legacy.map(|legacy| {
                if legacy {
                    ConfigAlgorithm::V1
                } else {
                    ConfigAlgorithm::V2
                }
            }),
            security_bits: self.security_bits,
            generation: self.generation,
            length: self.length,
            symbols: self.symbols,
        }
    }
}

fn canonical_profile_name(value: &str) -> String {
    value
        .nfc()
        .flat_map(char::to_lowercase)
        .collect::<String>()
        .nfc()
        .collect()
}

pub fn config_path() -> Result<PathBuf> {
    if let Some(path) = env::var_os("DESTINY_CONFIG") {
        if path.is_empty() {
            bail!("DESTINY_CONFIG is set but empty");
        }
        return Ok(PathBuf::from(path));
    }

    // Honor the old override and default location so the rename does not hide
    // an existing config or silently change already-enrolled passwords.
    if let Some(path) = env::var_os("ORACLE_CONFIG") {
        if path.is_empty() {
            bail!("ORACLE_CONFIG is set but empty");
        }
        return Ok(PathBuf::from(path));
    }

    let directories = ProjectDirs::from("", "", "destiny")
        .context("could not determine the platform config directory")?;
    let path = directories.config_dir().join("config.toml");
    let legacy_path = ProjectDirs::from("", "", "oracle")
        .context("could not determine the legacy platform config directory")?
        .config_dir()
        .join("config.toml");
    if !path.exists() && legacy_path.exists() {
        Ok(legacy_path)
    } else {
        Ok(path)
    }
}

fn reject_symlink(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("refusing symbolic-link config path {}", path.display())
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("could not inspect {}", path.display())),
    }
}

#[cfg(unix)]
fn verify_secure_config_path(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    reject_symlink(path)?;
    let metadata = fs::metadata(path)
        .with_context(|| format!("could not inspect config file {}", path.display()))?;
    verify_owner(path, &metadata)?;
    if metadata.mode() & 0o077 != 0 {
        bail!(
            "insecure permissions on {}: expected mode 0600 (run `chmod 600 '{}'`)",
            path.display(),
            path.display()
        );
    }
    if metadata.nlink() != 1 {
        bail!(
            "refusing config file with multiple hard links: {}",
            path.display()
        );
    }

    let parent = path
        .parent()
        .context("config path has no parent directory")?;
    let parent_metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("could not inspect config directory {}", parent.display()))?;
    if parent_metadata.file_type().is_symlink() {
        bail!(
            "refusing symbolic-link config directory {}",
            parent.display()
        );
    }
    verify_owner(parent, &parent_metadata)?;
    if parent_metadata.mode() & 0o077 != 0 {
        bail!(
            "insecure permissions on config directory {}: expected mode 0700",
            parent.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_secure_config_path(path: &Path) -> Result<()> {
    reject_symlink(path)
}

#[cfg(unix)]
fn verify_owner(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let current_uid = rustix::process::geteuid().as_raw();
    if metadata.uid() != current_uid {
        bail!("{} is not owned by the current user", path.display());
    }
    Ok(())
}

#[cfg(unix)]
fn prepare_directory(path: &Path, created: bool) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("could not inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("refusing symbolic-link config directory {}", path.display());
    }
    verify_owner(path, &metadata)?;
    if created {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("could not set permissions on {}", path.display()))?;
    } else if metadata.mode() & 0o077 != 0 {
        bail!(
            "insecure permissions on config directory {}: expected mode 0700",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn prepare_directory(path: &Path, _created: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("could not inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("refusing symbolic-link config directory {}", path.display());
    }
    Ok(())
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("could not set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("could not sync config directory {}", path.display()))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn higher_priority_values_win() {
        let base = ParameterOverrides {
            length: Some(12),
            symbols: Some(1),
            ..Default::default()
        };
        let higher = ParameterOverrides {
            length: Some(16),
            ..Default::default()
        };
        let merged = base.overlay(higher);
        assert_eq!(merged.length, Some(16));
        assert_eq!(merged.symbols, Some(1));
    }

    #[test]
    fn version_one_migration_preserves_implicit_v2() {
        let old =
            "version = 1\nemail = 'me@example.com'\n[hosts.site.parameters]\ngeneration = 2\n";
        let migrated = ConfigV1::parse_and_migrate(old, Path::new("test.toml")).unwrap();
        assert_eq!(migrated.defaults.algorithm, Some(ConfigAlgorithm::V2));
        assert_eq!(
            migrated
                .defaults
                .overlay(migrated.hosts["site"].parameters)
                .resolve()
                .algorithm,
            Algorithm::V2
        );
    }

    #[test]
    fn config_schema_rejects_a_password_field() {
        let parsed = toml::from_str::<Config>("version = 2\npassword = 'never'\n");
        assert!(parsed.is_err());
        let nested = toml::from_str::<Config>("version = 2\n[hosts.example]\npassword = 'never'\n");
        assert!(nested.is_err());
    }

    #[test]
    fn rejects_ambiguous_profile_names() {
        let mut config = Config::new();
        config.hosts.insert("Work".into(), HostProfile::default());
        config.hosts.insert("work".into(), HostProfile::default());
        assert!(config.validate().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn saved_config_has_private_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("config.toml");
        Config::new().save(&path).unwrap();
        assert_eq!(
            fs::metadata(directory.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_an_existing_shared_config_directory() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let error = Config::new()
            .save(&directory.path().join("config.toml"))
            .unwrap_err();
        assert!(error.to_string().contains("insecure permissions"));
    }
}
