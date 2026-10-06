//! Policy digest over the endpoint set (architecture §M8.5).
//!
//! A fingerprint of what the user is shown, not new encryption logic. The
//! desktop renderer recomputes it over the endpoint list it displays and
//! refuses the request on mismatch.
//!
//! 1. Per endpoint: `host \t port \t (path or "") \t source \n`.
//! 2. Sort the lines by byte order.
//! 3. Concatenate.
//! 4. SHA-256 of the UTF-8 bytes.
//! 5. `"sha256:" + lowercase hex`.

use sha2::{Digest, Sha256};

use crate::wire::Endpoint;

/// Compute the pinned policy digest for an endpoint set (order-independent).
pub fn policy_digest(endpoints: &[Endpoint]) -> String {
    let mut lines: Vec<String> = endpoints
        .iter()
        .map(|endpoint| {
            format!(
                "{}\t{}\t{}\t{}\n",
                endpoint.host,
                endpoint.port,
                endpoint.path.as_deref().unwrap_or(""),
                endpoint.source.as_str()
            )
        })
        .collect();
    lines.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

    let mut hasher = Sha256::new();
    for line in &lines {
        hasher.update(line.as_bytes());
    }
    let digest = hasher.finalize();

    let mut out = String::with_capacity(7 + 64);
    out.push_str("sha256:");
    for byte in digest {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
    out
}

/// `^sha256:[0-9a-f]{64}$`
pub fn is_valid_digest(candidate: &str) -> bool {
    candidate.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

fn hex_digit(nibble: u8) -> char {
    char::from(b"0123456789abcdef"[usize::from(nibble & 0x0f)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::EndpointSource;

    #[derive(serde::Deserialize)]
    struct Vectors {
        vectors: Vec<Vector>,
    }

    #[derive(serde::Deserialize)]
    struct Vector {
        endpoints: Vec<Endpoint>,
        digest: String,
    }

    fn vectors() -> Vectors {
        serde_json::from_str(include_str!(
            "../tests/fixtures/openshell-digest-vectors.json"
        ))
        .expect("vectors fixture parses")
    }

    #[test]
    fn fixture_vectors_match() {
        let vectors = vectors();
        assert_eq!(vectors.vectors.len(), 2);
        for vector in &vectors.vectors {
            assert!(is_valid_digest(&vector.digest));
            assert_eq!(policy_digest(&vector.endpoints), vector.digest);
        }
    }

    #[test]
    fn digest_is_independent_of_input_order() {
        for vector in vectors().vectors {
            let mut reversed = vector.endpoints.clone();
            reversed.reverse();
            assert_eq!(policy_digest(&reversed), vector.digest);
        }
    }

    #[test]
    fn contract_test_vectors_are_pinned() {
        let one = vec![Endpoint {
            host: "api.github.com".into(),
            port: 443,
            path: Some("/**".into()),
            source: EndpointSource::Profile,
        }];
        assert_eq!(
            policy_digest(&one),
            "sha256:998f40a71463c9250c9eaf7bcb560234fc838a2bf7592b260165f9b4af110020"
        );
        let mut two = one.clone();
        two.push(Endpoint {
            host: "uploads.github.com".into(),
            port: 443,
            path: None,
            source: EndpointSource::PolicyBinding,
        });
        assert_eq!(
            policy_digest(&two),
            "sha256:f098164656d916d933b9ad3ea24ce0c43cc84aa04300528a4e2e6ec2844e582d"
        );
    }

    #[test]
    fn digest_shape_validation() {
        assert!(!is_valid_digest("sha256:ABC"));
        assert!(!is_valid_digest(&format!("sha256:{}", "A".repeat(64))));
        assert!(!is_valid_digest(&format!("sha1:{}", "a".repeat(64))));
        assert!(is_valid_digest(&format!("sha256:{}", "a".repeat(64))));
    }
}
