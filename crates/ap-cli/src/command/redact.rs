//! Streaming output scrubber for `aac run`.
//!
//! Replaces every occurrence of a set of secret byte strings in a stream of
//! chunks with a fixed placeholder, without buffering the whole stream and
//! without letting a secret slip through when it straddles a chunk
//! boundary. Used to redact `password`/`totp`/`notes`/other secret-flagged
//! credential fields from a child process's stdout and stderr before they
//! are forwarded to *our* stdout/stderr.

/// Placeholder written in place of every matched secret.
pub const REDACTION_PLACEHOLDER: &str = "[redacted:aac]";

/// Streaming redactor. Feed it chunks via [`Redactor::push`]; call
/// [`Redactor::finish`] once, after the source is exhausted, to flush
/// anything still held back.
pub struct Redactor {
    /// Secrets to match, longest first — so that when one secret is a
    /// substring of another, the longer (more specific) match wins.
    secrets: Vec<Vec<u8>>,
    /// Length of the longest secret; drives how many trailing bytes must be
    /// held back across a `push` call in case a match straddles the chunk
    /// boundary.
    max_secret_len: usize,
    /// Bytes held back from the previous `push` call.
    carry: Vec<u8>,
}

impl Redactor {
    /// Build a redactor for the given secret values. Empty strings are
    /// ignored (an empty needle would match everywhere). Values are
    /// deduplicated implicitly by the match loop; duplicates are harmless.
    pub fn new(secrets: Vec<String>) -> Self {
        let mut secrets: Vec<Vec<u8>> = secrets
            .into_iter()
            .filter(|s| !s.is_empty())
            .map(String::into_bytes)
            .collect();
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        let max_secret_len = secrets.iter().map(Vec::len).max().unwrap_or(0);
        Self {
            secrets,
            max_secret_len,
            carry: Vec::new(),
        }
    }

    /// `true` when there is nothing to redact (no secrets, or all empty).
    /// Callers can skip the pump machinery entirely in this case.
    pub fn is_noop(&self) -> bool {
        self.secrets.is_empty()
    }

    /// Feed a chunk of output. Returns the bytes safe to emit now — some
    /// trailing bytes may be held back internally if they could be the
    /// start of a secret that continues in the next chunk.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(chunk);
        let hold = self.max_secret_len.saturating_sub(1);
        let (out, carry) = self.scan(buf, hold);
        self.carry = carry;
        out
    }

    /// Flush anything still held back. Call exactly once, after the last
    /// `push` (e.g. when the child process has exited and its stdio pipes
    /// are at EOF).
    pub fn finish(&mut self) -> Vec<u8> {
        let buf = std::mem::take(&mut self.carry);
        let (out, _leftover) = self.scan(buf, 0);
        out
    }

    /// Scan `buf`, redacting matches found strictly before
    /// `len(buf) - hold`. Bytes from that point on are returned as the new
    /// carry rather than being emitted, since a secret could still be
    /// forming across the next chunk boundary. `hold = 0` (used by
    /// `finish`) processes the whole buffer.
    ///
    /// Correctness: for any position `i < len(buf) - hold` (with
    /// `hold = max_secret_len - 1`), `i + max_secret_len <= len(buf)`, so
    /// every candidate secret's full length is available in `buf` at that
    /// position — a non-match there is a genuine non-match, not a
    /// truncated read.
    fn scan(&self, buf: Vec<u8>, hold: usize) -> (Vec<u8>, Vec<u8>) {
        if self.secrets.is_empty() {
            return (buf, Vec::new());
        }

        let safe_len = buf.len().saturating_sub(hold);
        let mut out = Vec::with_capacity(buf.len());
        let mut i = 0;
        while i < safe_len {
            match self.match_len_at(&buf, i) {
                Some(len) => {
                    out.extend_from_slice(REDACTION_PLACEHOLDER.as_bytes());
                    i += len;
                }
                None => {
                    out.push(buf[i]);
                    i += 1;
                }
            }
        }
        let carry = buf[i..].to_vec();
        (out, carry)
    }

    /// Longest secret matching at `buf[i..]`, if any (secrets are sorted
    /// longest-first, so the first hit is the longest).
    fn match_len_at(&self, buf: &[u8], i: usize) -> Option<usize> {
        self.secrets
            .iter()
            .find(|s| buf[i..].starts_with(s.as_slice()))
            .map(Vec::len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redact_all(secrets: Vec<&str>, chunks: &[&[u8]]) -> String {
        let mut redactor = Redactor::new(secrets.into_iter().map(str::to_string).collect());
        let mut out = Vec::new();
        for chunk in chunks {
            out.extend(redactor.push(chunk));
        }
        out.extend(redactor.finish());
        String::from_utf8(out).expect("valid utf8")
    }

    #[test]
    fn no_secrets_is_noop_and_passes_through() {
        let redactor = Redactor::new(vec![]);
        assert!(redactor.is_noop());
        assert_eq!(redact_all(vec![], &[b"hello world"]), "hello world");
    }

    #[test]
    fn single_secret_within_one_chunk() {
        assert_eq!(
            redact_all(vec!["hunter2"], &[b"login with hunter2 now"]),
            "login with [redacted:aac] now"
        );
    }

    #[test]
    fn secret_absent_passes_through_unchanged() {
        assert_eq!(
            redact_all(vec!["hunter2"], &[b"nothing secret here"]),
            "nothing secret here"
        );
    }

    #[test]
    fn secret_split_across_chunk_boundary() {
        // "hunter2" split as "hunt" | "er2"
        let out = redact_all(vec!["hunter2"], &[b"pw=hunt", b"er2 done"]);
        assert_eq!(out, "pw=[redacted:aac] done");
    }

    #[test]
    fn secret_split_byte_by_byte() {
        let secret = "s3cr3t";
        let chunks: Vec<&[u8]> = secret.as_bytes().iter().map(std::slice::from_ref).collect();
        let mut redactor = Redactor::new(vec![secret.to_string()]);
        let mut out = Vec::new();
        for chunk in &chunks {
            out.extend(redactor.push(chunk));
        }
        out.extend(redactor.finish());
        assert_eq!(String::from_utf8(out).expect("utf8"), "[redacted:aac]");
    }

    #[test]
    fn multiple_secrets_all_redacted() {
        let out = redact_all(
            vec!["hunter2", "654321"],
            &[b"user=admin pass=hunter2 totp=654321"],
        );
        assert_eq!(out, "user=admin pass=[redacted:aac] totp=[redacted:aac]");
    }

    #[test]
    fn overlapping_secrets_prefer_longest_match() {
        // "secret" is a prefix of "secret123" — the longer one must win
        // wherever it matches, so we don't leak the "123" suffix.
        let out = redact_all(vec!["secret", "secret123"], &[b"token=secret123!"]);
        assert_eq!(out, "token=[redacted:aac]!");
    }

    #[test]
    fn overlapping_secrets_shorter_still_matches_when_longer_absent() {
        let out = redact_all(vec!["secret", "secret123"], &[b"token=secret!"]);
        assert_eq!(out, "token=[redacted:aac]!");
    }

    #[test]
    fn secret_at_very_end_of_stream_flushed_by_finish() {
        // The secret sits entirely in the last `max_secret_len - 1` window
        // and is only ever recovered by finish()'s full-buffer scan.
        let out = redact_all(vec!["tail-secret"], &[b"prefix ", b"tail-secret"]);
        assert_eq!(out, "prefix [redacted:aac]");
    }

    #[test]
    fn incomplete_secret_at_true_eof_passes_through() {
        // No more data ever arrives, so the partial match can't be
        // completed — finish() must emit it literally, not drop it.
        let out = redact_all(vec!["hunter2"], &[b"pw=hunt"]);
        assert_eq!(out, "pw=hunt");
    }

    #[test]
    fn many_small_chunks_still_catch_the_secret() {
        let out = redact_all(
            vec!["topsecret"],
            &[b"a", b"b", b"top", b"se", b"cr", b"et", b"c"],
        );
        assert_eq!(out, "ab[redacted:aac]c");
    }

    #[test]
    fn empty_secret_values_are_ignored() {
        let out = redact_all(vec!["", "hunter2"], &[b"pw=hunter2"]);
        assert_eq!(out, "pw=[redacted:aac]");
    }
}
