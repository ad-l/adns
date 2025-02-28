#[cfg(test)]
mod tests {
    use crate::{AttestationPolicy, AttestationRecord, ResolverState};
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use hickory_resolver::proto::rr::{Name, RecordType};
    use std::collections::HashMap;
    use std::time::Duration;

    // Mock configuration for testing
    fn get_test_config() -> crate::ResolverConfig {
        crate::ResolverConfig {
            adns_roots: vec![
                crate::ADNSRootConfig {
                    name: "test.attested.name".to_string(),
                    trust_anchor: "AwEAAbOz2VLuTIMQ2rvKCJUd0fK94d5hWnILY5u+dQP1Z9EXO7M1vWubZEsYTI03GPogZR9/qjE2+QZxa9GAo1jNkiaKjzeEHZdlpGaQ+Q7DkNYeOK4LJp/+i3FVkR9zT6wveSbwdm/zUIuZ3EXf+d1T8omUCvN3hHRfwz+lUOmJL/2LFG4F9EZtYs/HyRKK7OZkBuC76+QQX/X5HgqKTLljf9KjBMTVWwC9/J0cy59nbmLOK98rQflm5dVTLH9q/lViBW8LiZ9oDejbCGplr6vt1YPRC/6MEcZfqKpLdJFwPVCH+5fHsIp4hdKgG6X3/TnHYYVwZpkRJ0l6luMNtFs79kU=".to_string(),
                    key_tag: 19036,
                    algorithm: 8,
                },
            ],
            bind_address: "127.0.0.1".to_string(),
            port: 0, // Use port 0 for tests (OS will assign an available port)
            cert_file: None,
            key_file: None,
            timeout_seconds: 5,
            max_concurrent_requests: 10,
        }
    }

    // Mock implementation of ResolverState for testing
    struct MockResolverState {
        config: crate::ResolverConfig,
        trust_anchors: HashMap<String, hickory_resolver::proto::rr::dnssec::DnssecTrustAnchor>,
    }

    impl MockResolverState {
        fn new(config: crate::ResolverConfig) -> Self {
            Self {
                config,
                trust_anchors: HashMap::new(),
            }
        }

        fn is_adns_domain(&self, domain: &str) -> Option<String> {
            for root in &self.config.adns_roots {
                if domain == root.name || domain.ends_with(&format!(".{}", root.name)) {
                    return Some(root.name.clone());
                }
            }
            None
        }

        fn validate_attestation(&self, attestation: &AttestationRecord, policy: &AttestationPolicy) -> bool {
            // Mock validation for testing
            attestation.attestation_data.contains("valid") && policy.policy_data.contains("valid")
        }
    }

    #[test]
    fn test_is_adns_domain() {
        let config = get_test_config();
        let state = MockResolverState::new(config);

        // Test domains that should match
        assert_eq!(
            state.is_adns_domain("test.attested.name"),
            Some("test.attested.name".to_string())
        );
        assert_eq!(
            state.is_adns_domain("service.test.attested.name"),
            Some("test.attested.name".to_string())
        );
        assert_eq!(
            state.is_adns_domain("api.service.test.attested.name"),
            Some("test.attested.name".to_string())
        );

        // Test domains that should not match
        assert_eq!(state.is_adns_domain("example.com"), None);
        assert_eq!(state.is_adns_domain("other.attested.name"), None);
        assert_eq!(state.is_adns_domain("test.attested.name.evil.com"), None);
    }

    #[test]
    fn test_attestation_validation() {
        let config = get_test_config();
        let state = MockResolverState::new(config);

        // Test valid attestation and policy
        let valid_attestation = AttestationRecord {
            attestation_data: "valid attestation data".to_string(),
        };
        let valid_policy = AttestationPolicy {
            policy_data: "valid policy data".to_string(),
        };
        assert!(state.validate_attestation(&valid_attestation, &valid_policy));

        // Test invalid attestation
        let invalid_attestation = AttestationRecord {
            attestation_data: "invalid attestation data".to_string(),
        };
        assert!(!state.validate_attestation(&invalid_attestation, &valid_policy));

        // Test invalid policy
        let invalid_policy = AttestationPolicy {
            policy_data: "invalid policy data".to_string(),
        };
        assert!(!state.validate_attestation(&valid_attestation, &invalid_policy));
    }

    // Tests that would require network access are marked as ignored by default
    #[ignore]
    #[tokio::test]
    async fn test_fetch_attestation() {
        // This test requires network access and would test the real implementation
        // It's marked as ignored to avoid depending on network in regular test runs
        let config = get_test_config();
        
        // In a real test, we would:
        // 1. Start a mock DNS server
        // 2. Configure it to respond to _attest.example.test.attested.name
        // 3. Create a real ResolverState pointing to our mock server
        // 4. Test the fetch_attestation method
    }

    #[ignore]
    #[tokio::test]
    async fn test_fetch_policy() {
        // Similar to test_fetch_attestation, but for policies
    }

    #[test]
    fn test_build_trust_anchor() {
        let root_config = crate::ADNSRootConfig {
            name: "test.attested.name".to_string(),
            trust_anchor: "AwEAAcWUPJ0Z/L5TamQT3WvwOAGGMQkKKCxX72Qvg89ycc+Cq/rYNg/18P1UHDiJNJgKLsRRr32rwESDj/oCFqYRm+dO/qZP+SUDDgqGfKHU9x2zfqs/sEy+o9Op83VQjMa3ENo2nqBMVYI2Bma3BA7Fy7+6KNqHnZ/Og7qGZEEVCNA9".to_string(),
            key_tag: 12345,
            algorithm: 8,
        };

        // In a real test, we would call ResolverState::build_trust_anchor and
        // verify the result contains the expected key information
    }

    #[test]
    fn test_validate_dnssec() {
        // This test would verify DNSSEC validation logic
        // It would require mocking the DNS responses with valid DNSSEC chains
    }
}
