use anyhow::{bail, Context, Result};
use arboard::Clipboard;
use std::{
    io::{BufRead, BufReader, Read, Write},
    process::{Command, Stdio},
    thread,
    time::Duration,
};
use zeroize::Zeroizing;

const SERVICE_OK: &str = "destiny-clipboard-ready";

/// Launch a short-lived copy service. The generated password crosses only an
/// anonymous stdin pipe; it never appears in argv, the environment, or a file.
/// Keeping the service alive also makes clipboard ownership reliable on Linux.
pub fn copy(value: &str, clear_after_seconds: u32) -> Result<()> {
    let executable = std::env::current_exe().context("could not locate the destiny executable")?;
    let mut child = Command::new(executable)
        .arg("__clipboard-service")
        .arg(clear_after_seconds.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("could not start the private clipboard service")?;

    {
        let mut input = child
            .stdin
            .take()
            .context("clipboard service did not open its private input")?;
        input
            .write_all(value.as_bytes())
            .context("could not send the password to the clipboard service")?;
    }

    let output = child
        .stdout
        .take()
        .context("clipboard service did not open its status channel")?;
    let mut status = Zeroizing::new(String::new());
    BufReader::new(output)
        .read_line(&mut status)
        .context("could not read clipboard service status")?;
    if status.trim_end() != SERVICE_OK {
        let exit_status = child
            .wait()
            .context("could not wait for clipboard service")?;
        bail!(
            "clipboard service failed ({exit_status}): {}",
            status
                .trim_end()
                .strip_prefix("error: ")
                .unwrap_or("no status")
        );
    }

    // Dropping Child does not terminate it. It continues holding the native
    // clipboard and exits after clearing it or observing replacement content.
    Ok(())
}

pub fn run_service(clear_after_seconds: u32) -> Result<()> {
    let mut expected = Zeroizing::new(String::new());
    std::io::stdin()
        .read_to_string(&mut expected)
        .context("could not read private clipboard input")?;
    if expected.is_empty() {
        bail!("clipboard input was empty");
    }

    let result = serve(&expected, clear_after_seconds);
    if let Err(error) = &result {
        println!("error: {error:#}");
        std::io::stdout().flush().ok();
    }
    result
}

fn serve(expected: &str, clear_after_seconds: u32) -> Result<()> {
    let mut clipboard = match Clipboard::new() {
        Ok(clipboard) => clipboard,
        Err(error) => return fallback_clipboard(expected, clear_after_seconds, error),
    };
    set_secret(&mut clipboard, expected)?;

    acknowledge_copy()?;

    if clear_after_seconds == 0 {
        loop {
            thread::sleep(Duration::from_secs(1));
            if !clipboard_matches(&mut clipboard, expected) {
                return Ok(());
            }
        }
    }

    thread::sleep(Duration::from_secs(u64::from(clear_after_seconds)));
    if clipboard_matches(&mut clipboard, expected) {
        clipboard.clear().context("could not clear the clipboard")?;
    }
    Ok(())
}

fn acknowledge_copy() -> Result<()> {
    println!("{SERVICE_OK}");
    std::io::stdout()
        .flush()
        .context("could not acknowledge clipboard copy")
}

#[cfg(target_os = "macos")]
fn fallback_clipboard(
    expected: &str,
    clear_after_seconds: u32,
    _native_error: arboard::Error,
) -> Result<()> {
    // Some non-GUI launch contexts cannot open NSPasteboard directly. These
    // are fixed, OS-owned absolute paths—not PATH-resolved helper commands.
    macos_pbcopy(expected)?;
    acknowledge_copy()?;

    if clear_after_seconds == 0 {
        loop {
            thread::sleep(Duration::from_secs(1));
            if !macos_clipboard_matches(expected) {
                return Ok(());
            }
        }
    }

    thread::sleep(Duration::from_secs(u64::from(clear_after_seconds)));
    if macos_clipboard_matches(expected) {
        macos_pbcopy("")?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_pbcopy(value: &str) -> Result<()> {
    let mut child = Command::new("/usr/bin/pbcopy")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("could not start /usr/bin/pbcopy")?;
    child
        .stdin
        .as_mut()
        .context("pbcopy did not open stdin")?
        .write_all(value.as_bytes())
        .context("could not write to pbcopy")?;
    let output = child
        .wait_with_output()
        .context("could not wait for pbcopy")?;
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        bail!(
            "/usr/bin/pbcopy failed with {}: {}",
            output.status,
            error.trim()
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_clipboard_matches(expected: &str) -> bool {
    Command::new("/usr/bin/pbpaste")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map(|output| Zeroizing::new(output.stdout))
        .is_ok_and(|current| current.as_slice() == expected.as_bytes())
}

#[cfg(not(target_os = "macos"))]
fn fallback_clipboard(
    _expected: &str,
    _clear_after_seconds: u32,
    native_error: arboard::Error,
) -> Result<()> {
    Err(native_error).context("native clipboard is unavailable")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn set_secret(clipboard: &mut Clipboard, value: &str) -> Result<()> {
    use arboard::SetExtLinux;
    clipboard
        .set()
        .exclude_from_history()
        .text(value.to_owned())
        .context("could not copy password to the native clipboard")
}

#[cfg(target_os = "macos")]
fn set_secret(clipboard: &mut Clipboard, value: &str) -> Result<()> {
    use arboard::SetExtApple;
    clipboard
        .set()
        .exclude_from_history()
        .text(value.to_owned())
        .context("could not copy password to the native clipboard")
}

#[cfg(target_os = "windows")]
fn set_secret(clipboard: &mut Clipboard, value: &str) -> Result<()> {
    use arboard::SetExtWindows;
    clipboard
        .set()
        .exclude_from_monitoring()
        .text(value.to_owned())
        .context("could not copy password to the native clipboard")
}

#[cfg(all(not(unix), not(target_os = "windows")))]
fn set_secret(_clipboard: &mut Clipboard, _value: &str) -> Result<()> {
    bail!("clipboard integration is unavailable on this platform; use --print")
}

fn clipboard_matches(clipboard: &mut Clipboard, expected: &str) -> bool {
    clipboard
        .get_text()
        .map(Zeroizing::new)
        .is_ok_and(|current| current.as_bytes() == expected.as_bytes())
}
