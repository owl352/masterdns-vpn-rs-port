//! Port of `internal/logger` (logger.go + color_support_{unix,windows}.go).

use std::fs::{File, OpenOptions};
use std::io::{IsTerminal, Write};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const LEVEL_DEBUG: u8 = 0;
pub const LEVEL_INFO: u8 = 1;
pub const LEVEL_WARN: u8 = 2;
pub const LEVEL_ERROR: u8 = 3;

const PLAIN_LEVEL_TEXTS: [&str; 4] = ["[DEBUG]", "[INFO]", "[WARN]", "[ERROR]"];
const COLORED_LEVEL_TEXTS: [&str; 4] = [
    "\x1b[35m[DEBUG]\x1b[0m",
    "\x1b[32m[INFO]\x1b[0m",
    "\x1b[33m[WARN]\x1b[0m",
    "\x1b[31m[ERROR]\x1b[0m",
];

fn color_code(name: &str) -> Option<&'static str> {
    Some(match name {
        "black" => "\x1b[30m",
        "red" => "\x1b[31m",
        "green" => "\x1b[32m",
        "yellow" => "\x1b[33m",
        "blue" => "\x1b[34m",
        "magenta" => "\x1b[35m",
        "cyan" => "\x1b[36m",
        "white" => "\x1b[37m",
        "gray" | "grey" => "\x1b[90m",
        "bold" => "\x1b[1m",
        "reset" => "\x1b[0m",
        _ => return None,
    })
}

struct FileState {
    writer: Option<File>,
}

pub struct Logger {
    level: u8,
    color: bool,
    app_name_text: String,
    app_name_colored: String,
    file: Mutex<FileState>,
}

impl Logger {
    pub fn new(name: &str, raw_level: &str) -> Self {
        Self::with_file(name, raw_level, None)
    }

    pub fn with_file(name: &str, raw_level: &str, file_path: Option<&str>) -> Self {
        let app_name = format!("[{name}]");
        let file_writer = file_path.and_then(|path| OpenOptions::new().append(true).create(true).open(path).ok());

        Logger {
            level: parse_level(raw_level),
            color: should_use_color(),
            app_name_text: app_name.clone(),
            app_name_colored: format!("\x1b[36m{app_name}\x1b[0m"),
            file: Mutex::new(FileState { writer: file_writer }),
        }
    }

    pub fn enabled(&self, level: u8) -> bool {
        level >= self.level
    }

    fn logf(&self, level: u8, msg: &str) {
        if level < self.level {
            return;
        }

        let plain_msg = if msg.as_bytes().contains(&b'<') { strip_color_tags(msg) } else { msg.to_string() };

        let ts = format_timestamp();

        {
            let mut state = self.file.lock().unwrap();
            if let Some(file) = state.writer.as_mut() {
                let line = format!("{ts} {} {plain_msg}\n", PLAIN_LEVEL_TEXTS[level as usize]);
                if file.write_all(line.as_bytes()).is_err() {
                    state.writer = None;
                }
            }
        }

        let (app_name, level_text, final_msg): (&str, &str, String) = if self.color {
            let rendered = if msg.as_bytes().contains(&b'<') { render_color_tags(msg) } else { msg.to_string() };
            (&self.app_name_colored, COLORED_LEVEL_TEXTS[level as usize], rendered)
        } else {
            (&self.app_name_text, PLAIN_LEVEL_TEXTS[level as usize], plain_msg)
        };

        println!("{ts} {app_name} {level_text} {final_msg}");
    }

    pub fn debugf(&self, msg: &str) {
        self.logf(LEVEL_DEBUG, msg);
    }
    pub fn infof(&self, msg: &str) {
        self.logf(LEVEL_INFO, msg);
    }
    pub fn warnf(&self, msg: &str) {
        self.logf(LEVEL_WARN, msg);
    }
    pub fn errorf(&self, msg: &str) {
        self.logf(LEVEL_ERROR, msg);
    }
}

fn parse_level(raw: &str) -> u8 {
    match raw.trim().to_uppercase().as_str() {
        "DEBUG" => LEVEL_DEBUG,
        "WARNING" | "WARN" => LEVEL_WARN,
        "ERROR" | "CRITICAL" => LEVEL_ERROR,
        _ => LEVEL_INFO,
    }
}

fn format_timestamp() -> String {
    // Matches Go's "2006/01/02 15:04:05" format, computed without pulling in a
    // chrono-style dependency: a small manual civil-from-days conversion (UTC).
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs() as i64;
    let days = secs.div_euclid(86400);
    let time_of_day = secs.rem_euclid(86400);
    let (h, m, s) = (time_of_day / 3600, (time_of_day % 3600) / 60, time_of_day % 60);

    // Civil calendar algorithm (Howard Hinnant's days_from_civil, inverted).
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m2 = if mp < 10 { mp + 3 } else { mp - 9 };
    let y2 = if m2 <= 2 { y + 1 } else { y };

    format!("{y2:04}/{m2:02}/{d:02} {h:02}:{m:02}:{s:02}")
}

fn should_use_color() -> bool {
    if std::env::var("NO_COLOR").map(|v| !v.trim().is_empty()).unwrap_or(false) {
        return false;
    }
    if std::env::var("FORCE_COLOR").map(|v| !v.trim().is_empty()).unwrap_or(false) {
        return true;
    }
    detect_color_support()
}

#[cfg(windows)]
fn detect_color_support() -> bool {
    if !std::io::stdout().is_terminal() {
        return false;
    }
    enable_ansi_support::enable_ansi_support().is_ok()
}

#[cfg(not(windows))]
fn detect_color_support() -> bool {
    std::io::stdout().is_terminal()
}

fn parse_color_tag(tag: &str) -> Option<(String, bool)> {
    if tag.len() < 3 || !tag.starts_with('<') || !tag.ends_with('>') {
        return None;
    }
    let closing = tag.starts_with("</");
    let name = if closing { &tag[2..tag.len() - 1] } else { &tag[1..tag.len() - 1] };
    color_code(name)?;
    Some((name.to_string(), closing))
}

fn strip_color_tags(text: &str) -> String {
    if !text.as_bytes().contains(&b'<') {
        return text.to_string();
    }

    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            let next = bytes[i..].iter().position(|&b| b == b'<');
            match next {
                None => {
                    out.push_str(&text[i..]);
                    break;
                }
                Some(off) => {
                    out.push_str(&text[i..i + off]);
                    i += off;
                    continue;
                }
            }
        }

        let end = bytes[i..].iter().position(|&b| b == b'>');
        match end {
            None => {
                out.push_str(&text[i..]);
                break;
            }
            Some(off) => {
                let raw_tag = &text[i..i + off + 1];
                let lower = raw_tag.to_lowercase();
                if parse_color_tag(&lower).is_some() {
                    // dropped
                } else {
                    out.push_str(raw_tag);
                }
                i += off + 1;
            }
        }
    }
    out
}

fn render_color_tags(text: &str) -> String {
    let bytes = text.as_bytes();
    let start = match bytes.iter().position(|&b| b == b'<') {
        Some(s) => s,
        None => return text.to_string(),
    };

    let mut out = String::with_capacity(text.len() + 16);
    out.push_str(&text[..start]);
    let mut stack: Vec<String> = Vec::with_capacity(4);

    let mut i = start;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            let next = bytes[i..].iter().position(|&b| b == b'<');
            match next {
                None => {
                    out.push_str(&text[i..]);
                    break;
                }
                Some(off) => {
                    out.push_str(&text[i..i + off]);
                    i += off;
                    continue;
                }
            }
        }

        let end = bytes[i..].iter().position(|&b| b == b'>');
        let off = match end {
            None => {
                out.push_str(&text[i..]);
                break;
            }
            Some(off) => off,
        };

        let raw_tag = &text[i..i + off + 1];
        let lower = raw_tag.to_lowercase();
        match parse_color_tag(&lower) {
            Some((name, closing)) => {
                if closing {
                    if name == "reset" {
                        stack.clear();
                        out.push_str("\x1b[0m");
                    } else if restore_color_tag(&mut stack, &name) {
                        out.push_str("\x1b[0m");
                        for active in &stack {
                            out.push_str(color_code(active).unwrap_or(""));
                        }
                    } else {
                        out.push_str(raw_tag);
                    }
                } else {
                    out.push_str(color_code(&name).unwrap_or(""));
                    stack.push(name);
                }
            }
            None => out.push_str(raw_tag),
        }
        i += off + 1;
    }

    if !stack.is_empty() {
        out.push_str("\x1b[0m");
    }

    out
}

fn restore_color_tag(stack: &mut Vec<String>, name: &str) -> bool {
    if let Some(idx) = stack.iter().rposition(|n| n == name) {
        stack.remove(idx);
        true
    } else {
        false
    }
}

impl arq::ArqLogger for Logger {
    fn debugf(&self, msg: &str) {
        Logger::debugf(self, msg);
    }
    fn infof(&self, msg: &str) {
        Logger::infof(self, msg);
    }
    fn errorf(&self, msg: &str) {
        Logger::errorf(self, msg);
    }
}

pub fn now_unix_nano() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_known_tags_leaves_unknown() {
        let input = "<red>hello</red> <bogus>world</bogus>";
        assert_eq!(strip_color_tags(input), "hello <bogus>world</bogus>");
    }

    #[test]
    fn renders_nested_tags_and_restores_stack() {
        let input = "<red><bold>x</red>y</bold>";
        let rendered = render_color_tags(input);
        // red pushed, bold pushed, x, closing </red> removes "red" from the
        // stack (not necessarily the top) and reapplies remaining active codes.
        assert!(rendered.contains("\x1b[31m")); // red
        assert!(rendered.contains("\x1b[1m")); // bold
        assert!(rendered.ends_with("\x1b[0m"));
    }

    #[test]
    fn plain_text_without_tags_is_unchanged() {
        assert_eq!(strip_color_tags("no tags here"), "no tags here");
        assert_eq!(render_color_tags("no tags here"), "no tags here");
    }

    #[test]
    fn level_gating() {
        let logger = Logger { level: LEVEL_WARN, ..dummy() };
        assert!(!logger.enabled(LEVEL_DEBUG));
        assert!(!logger.enabled(LEVEL_INFO));
        assert!(logger.enabled(LEVEL_WARN));
        assert!(logger.enabled(LEVEL_ERROR));
    }

    fn dummy() -> Logger {
        Logger {
            level: LEVEL_INFO,
            color: false,
            app_name_text: "[test]".to_string(),
            app_name_colored: "[test]".to_string(),
            file: Mutex::new(FileState { writer: None }),
        }
    }
}
