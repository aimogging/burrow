//! Parse `~/.ssh/config` (recursively, following `Include` directives)
//! and return the list of bare aliases — the things you can `ssh <name>`
//! to. Skips wildcard / negated patterns since they're config blocks,
//! not real targets.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// All concrete `Host` aliases declared in the user's ssh config and
/// any files it Includes. Best-effort — silently returns an empty Vec
/// on missing config / IO errors.
pub fn fetch_ssh_aliases() -> Vec<String> {
    let Some(home) = home_dir() else { return Vec::new() };
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    walk(&home.join(".ssh").join("config"), &home, &mut out, &mut seen);
    let mut s = HashSet::new();
    out.into_iter().filter(|n| s.insert(n.clone())).collect()
}

fn walk(path: &Path, home: &Path, out: &mut Vec<String>, seen: &mut HashSet<PathBuf>) {
    let canon = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if !seen.insert(canon) {
        return;
    }
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    for line in content.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = strip_keyword(trimmed, "Host") {
            for name in rest.split_whitespace() {
                if !name.contains('*') && !name.contains('?') && !name.starts_with('!') {
                    out.push(name.to_string());
                }
            }
        } else if let Some(rest) = strip_keyword(trimmed, "Include") {
            for raw in rest.split_whitespace() {
                let pat = expand(raw, home);
                let resolved = if pat.is_absolute() {
                    pat
                } else {
                    home.join(".ssh").join(pat)
                };
                for p in glob_files(&resolved) {
                    walk(&p, home, out, seen);
                }
            }
        }
    }
}

/// Match `Host` / `Include` / etc. case-insensitively, followed by
/// whitespace or `=`. Returns the rest of the line after that
/// separator (and any extra spaces / `=`).
fn strip_keyword<'a>(s: &'a str, kw: &str) -> Option<&'a str> {
    if s.len() <= kw.len() {
        return None;
    }
    if !s.as_bytes()[..kw.len()].eq_ignore_ascii_case(kw.as_bytes()) {
        return None;
    }
    let next = &s[kw.len()..];
    let first = next.as_bytes()[0];
    if matches!(first, b' ' | b'\t' | b'=') {
        Some(next.trim_start_matches(|c: char| c == '=' || c == ' ' || c == '\t'))
    } else {
        None
    }
}

fn expand(s: &str, home: &Path) -> PathBuf {
    if let Some(rest) = s.strip_prefix("~/") {
        home.join(rest)
    } else if s == "~" {
        home.to_path_buf()
    } else {
        PathBuf::from(s)
    }
}

fn home_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    } else {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

/// Tiny glob — `*` and `?` only, applied to the leaf component. Path
/// segments above the wildcard are taken literally. Covers the
/// realistic `Include ~/.ssh/config.d/*` shape; nothing fancier.
fn glob_files(pat: &Path) -> Vec<PathBuf> {
    let s = pat.to_string_lossy();
    if !s.contains('*') && !s.contains('?') {
        return if pat.is_file() {
            vec![pat.to_path_buf()]
        } else {
            Vec::new()
        };
    }
    let parent = pat.parent().unwrap_or_else(|| Path::new("."));
    let leaf = pat.file_name().and_then(|f| f.to_str()).unwrap_or("");
    let Ok(rd) = std::fs::read_dir(parent) else {
        return Vec::new();
    };
    rd.flatten()
        .filter(|e| {
            e.file_name()
                .to_str()
                .map(|n| glob_match(leaf, n))
                .unwrap_or(false)
        })
        .map(|e| e.path())
        .collect()
}

fn glob_match(pat: &str, name: &str) -> bool {
    let p = pat.as_bytes();
    let n = name.as_bytes();
    let (mut pi, mut ni) = (0usize, 0usize);
    let (mut star_pi, mut star_ni): (Option<usize>, usize) = (None, 0);
    while ni < n.len() {
        if pi < p.len() && p[pi] == b'?' {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star_pi = Some(pi);
            star_ni = ni;
            pi += 1;
        } else if pi < p.len() && p[pi] == n[ni] {
            pi += 1;
            ni += 1;
        } else if let Some(s) = star_pi {
            pi = s + 1;
            star_ni += 1;
            ni = star_ni;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn glob_basics() {
        assert!(glob_match("*.conf", "burrow.conf"));
        assert!(glob_match("*.conf", ".conf"));
        assert!(!glob_match("*.conf", "burrow.txt"));
        assert!(glob_match("config-?", "config-a"));
        assert!(!glob_match("config-?", "config-ab"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("foo*bar", "foozbar"));
        assert!(glob_match("foo*bar", "foobar"));
        assert!(!glob_match("foo*bar", "foozbaz"));
    }

    #[test]
    fn strip_keyword_case_insensitive_and_eq_separator() {
        assert_eq!(strip_keyword("Host alias1", "Host"), Some("alias1"));
        assert_eq!(strip_keyword("HOST   alias1", "Host"), Some("alias1"));
        assert_eq!(strip_keyword("host=alias1", "Host"), Some("alias1"));
        assert_eq!(strip_keyword("HostName foo", "Host"), None);
    }

    #[test]
    fn end_to_end_with_include() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let ssh = home.join(".ssh");
        let conf_d = ssh.join("config.d");
        fs::create_dir_all(&conf_d).unwrap();

        fs::write(
            ssh.join("config"),
            "Host main1 main2\n  HostName 10.0.0.1\nHost *\n  User root\nInclude ~/.ssh/config.d/*\n",
        )
        .unwrap();
        fs::write(conf_d.join("a.conf"), "Host included1\n").unwrap();
        fs::write(conf_d.join("b.conf"), "Host included2 included3\n").unwrap();

        // Drive `walk` directly with the temp dir — fetch_ssh_aliases
        // reads $HOME so we'd have to mutate the env globally, which
        // races other tests. walk() is the same code with one less
        // step.
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        walk(&ssh.join("config"), home, &mut out, &mut seen);
        out.sort();
        assert_eq!(
            out,
            vec![
                "included1".to_string(),
                "included2".to_string(),
                "included3".to_string(),
                "main1".to_string(),
                "main2".to_string(),
            ]
        );
    }

    #[test]
    fn missing_file_returns_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        walk(&tmp.path().join("nope"), tmp.path(), &mut out, &mut seen);
        assert!(out.is_empty());
    }
}
