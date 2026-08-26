// Copyright (c) 2026 sal
// SPDX-License-Identifier: MIT
//! Style — TTY-aware ANSI helpers for stylised CLI output.
//! Honours `NO_COLOR` and `is_terminal()`. No external colour crate.

use crate::control::ControlStatus;
use std::io::IsTerminal;

fn use_color() -> bool {
    if std::env::var("NO_COLOR").is_ok() {
        return false;
    }
    if std::env::var("ISOPOD_NO_COLOR").is_ok() {
        return false;
    }
    std::io::stdout().is_terminal()
}

fn c(code: &str, s: &str) -> String {
    if use_color() {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

pub fn bold(s: impl AsRef<str>) -> String {
    c("1", s.as_ref())
}
pub fn dim(s: impl AsRef<str>) -> String {
    c("2", s.as_ref())
}
pub fn red(s: impl AsRef<str>) -> String {
    c("31", s.as_ref())
}
pub fn green(s: impl AsRef<str>) -> String {
    c("32", s.as_ref())
}
pub fn yellow(s: impl AsRef<str>) -> String {
    c("33", s.as_ref())
}
pub fn blue(s: impl AsRef<str>) -> String {
    c("34", s.as_ref())
}
pub fn cyan(s: impl AsRef<str>) -> String {
    c("36", s.as_ref())
}
pub fn magenta(s: impl AsRef<str>) -> String {
    c("35", s.as_ref())
}
pub fn path(s: impl AsRef<str>) -> String {
    cyan(s)
}
pub fn id(s: impl AsRef<str>) -> String {
    cyan(s)
}

pub fn status(s: &ControlStatus) -> String {
    match s {
        ControlStatus::Pass => green("PASS"),
        ControlStatus::Fail => red("FAIL"),
        ControlStatus::Warning => yellow("WARN"),
        ControlStatus::Unknown => dim("UNKNOWN"),
    }
}

pub fn status_with_icon(s: &ControlStatus) -> String {
    match s {
        ControlStatus::Pass => format!("{} {}", green("●"), green("PASS")),
        ControlStatus::Fail => format!("{} {}", red("●"), red("FAIL")),
        ControlStatus::Warning => format!("{} {}", yellow("●"), yellow("WARN")),
        ControlStatus::Unknown => format!("{} {}", dim("○"), dim("UNKNOWN")),
    }
}

pub fn confidence_bar(conf: f32) -> String {
    let pct = (conf * 100.0).round() as u8;
    let filled = ((pct as f32 / 100.0 * 10.0).round() as usize).min(10);
    let empty = 10 - filled;
    let bar = format!("{}{}", "█".repeat(filled), "░".repeat(empty));
    let colored = match pct {
        0..=49 => red(&bar),
        50..=74 => yellow(&bar),
        _ => green(&bar),
    };
    format!("{colored} {:>3}%", pct)
}

pub fn header(title: &str) -> String {
    let line = "─".repeat(title.len() + 2);
    format!(
        "{}\n {} \n{}",
        dim(format!("┌{}┐", line)),
        bold(title),
        dim(format!("└{}┘", line))
    )
}

pub fn banner() -> String {
    if use_color() {
        format!(
            "{}\n{}  {}\n{}",
            dim("┌─────────────────────────────────────────────────┐"),
            blue("│"),
            bold("  isopod  ·  compliance nervous system            "),
            dim("└─────────────────────────────────────────────────┘")
        )
    } else {
        "isopod — compliance nervous system".to_string()
    }
}

pub fn kv(key: &str, value: &str) -> String {
    format!("{} {}", dim(format!("{key}:")), value)
}
