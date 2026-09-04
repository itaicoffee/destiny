#[cfg(unix)]
use anyhow::Context;
use anyhow::Result;

/// Reduce exposure of the master password through crash dumps and, on Linux,
/// process tracing/procfs memory reads. This runs before any secret is read.
pub fn harden_process() -> Result<()> {
    #[cfg(unix)]
    {
        use rustix::process::{setrlimit, Resource, Rlimit};
        setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        )
        .context("could not disable process core dumps")?;
    }

    #[cfg(target_os = "linux")]
    {
        use rustix::process::{set_dumpable_behavior, DumpableBehavior};
        set_dumpable_behavior(DumpableBehavior::NotDumpable)
            .context("could not disable process dumpability")?;
    }

    Ok(())
}
