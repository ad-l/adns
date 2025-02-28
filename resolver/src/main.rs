//! Attested DNS Resolver with DNS over HTTPS support
//!
//! This resolver extends standard DNS with DNSSEC validation and attestation verification
//! for domains under configured aDNS roots.

use std::collections::HashMap;
use std::sync::Arc;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use std::fs;
use std::path::Path;

use tokio::sync::RwLock;
use warp::{Filter, Reply};
use serde::{Deserialize, Serialize};
use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
    proto::{
        error::ProtoError,
        rr::{
            dnssec::{Algorithm, DnssecError, DnssecResult, DnssecTrustAnchor, TrustAnchor},
            Record, DNSClass, Name, RData, RecordType,
        },
        op::Query,
    },
};
use hickory_server::store::in_memory::InMemoryAuthority;
use bytes::{Bytes, BytesMut};
use log::{debug, error, info, warn};
use anyhow::{Result, Context, anyhow};
use serde_json::Value;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

// Configuration structs
#[derive(Debug, Deserialize, Clone)]
struct ADNSRootConfig {
    /// Domain name of the aDNS root
    name: String,
    /// Base64-encoded DNSSEC trust anchor (DS or DNSKEY record)
    trust_anchor: String,
    /// Key tag for the trust anchor
    key_tag: u16,
    /// Algorithm for the trust anchor
    algorithm: u8,
}

#[derive(Debug, Deserialize, Clone)]
struct ResolverConfig {
    /// List of aDNS roots with pinned DNSSEC KSKs
    adns_roots: Vec<ADNSRootConfig>,
    /// Address to bind the DoH server to
    bind_address: String,
    /// Port to bind the DoH server to
    port: u16,
    /// Path to certificate file for TLS
    cert_file: Option<String>,
    /// Path to private key file for TLS
    key_file: Option<String>,
    /// Timeout for DNS queries in seconds
    timeout_seconds: u64,
    /// Maximum number of concurrent requests
    max_concurrent_requests: usize,
}

#[derive(Debug, Clone)]
struct AttestationPolicy {
    // Placeholder for policy data
    policy_data: String,
}

/// Structure to hold attestation records
#[derive(Debug, Clone)]
struct AttestationRecord {
    // Placeholder for attestation data
    attestation_data: String,
}

/// State of the resolver
struct ResolverState {
    /// Main resolver configuration
    config: ResolverConfig,
    /// Trust anchors for aDNS roots
    trust_anchors: HashMap<String, DnssecTrustAnchor>,
    /// The DNS resolver
    resolver: TokioAsyncResolver,
}

impl ResolverState {
    /// Create a new resolver state from configuration
    async fn new(config: ResolverConfig) -> Result<Self> {
        // Build trust anchors for all configured aDNS roots
        let mut trust_anchors = HashMap::new();
        for root in &config.adns_roots {
            let anchor = Self::build_trust_anchor(root)?;
            trust_anchors.insert(root.name.clone(), anchor);
        }

        // Create resolver with system nameservers
        let mut resolver_config = hickory_resolver::config::ResolverConfig::new();
        
        // Use system nameservers, usually from /etc/resolv.conf
        // On most systems, this will be the ISP's DNS servers
        if let Ok(system_config) = hickory_resolver::system_conf::read_system_conf() {
            for ns in system_config.0.name_servers() {
                resolver_config.add_name_server(ns.clone());
            }
        } else {
            // Fallback to Cloudflare and Google if system config not available
            resolver_config.add_name_server(NameServerConfig::new(
                SocketAddr::new(IpAddr::from([1, 1, 1, 1]), 53),
                Protocol::Udp,
            ));
            resolver_config.add_name_server(NameServerConfig::new(
                SocketAddr::new(IpAddr::from([8, 8, 8, 8]), 53),
                Protocol::Udp,
            ));
        }

        // Configure resolver options
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(config.timeout_seconds);
        opts.attempts = 3;
        opts.validate = false; // We'll do our own DNSSEC validation
        opts.preserve_intermediates = true;
        
        // Create the async resolver
        let resolver = TokioAsyncResolver::tokio(resolver_config, opts);

        Ok(Self {
            config,
            trust_anchors,
            resolver,
        })
    }

    /// Build a DNSSEC trust anchor from an aDNS root configuration
    fn build_trust_anchor(root: &ADNSRootConfig) -> Result<DnssecTrustAnchor> {
        let domain = root.name.clone();
        
        // Decode the base64 trust anchor
        let key_data = BASE64.decode(&root.trust_anchor)
            .context("Failed to decode trust anchor")?;
        
        // Create name for the domain
        let name = Name::from_ascii(&domain)
            .map_err(|e| anyhow!("Invalid domain name {}: {}", domain, e))?;
            
        // Create a trust anchor using the key tag, algorithm, and key data
        let algorithm = Algorithm::from_u8(root.algorithm)
            .ok_or_else(|| anyhow!("Invalid algorithm: {}", root.algorithm))?;
            
        let trust_anchor = TrustAnchor::new(
            name,
            DNSClass::IN,
            root.key_tag,
            algorithm,
            key_data,
        );
        
        // Create a DNSSEC trust anchor with the single trust anchor
        let mut anchors = DnssecTrustAnchor::new();
        anchors.insert_trust_anchor(trust_anchor);
        
        Ok(anchors)
    }

    /// Check if a domain is under one of our configured aDNS roots
    fn is_adns_domain(&self, domain: &str) -> Option<String> {
        for root in &self.config.adns_roots {
            if domain == root.name || domain.ends_with(&format!(".{}", root.name)) {
                return Some(root.name.clone());
            }
        }
        None
    }

    /// Fetches attestation record for a given domain
    async fn fetch_attestation(&self, domain: &str) -> Result<Option<AttestationRecord>> {
        // Construct the name for the ATTEST record
        let attest_query = format!("_attest.{}", domain);
        let query_name = Name::from_ascii(&attest_query)?;
        
        // Query for TXT record that contains the attestation data
        match self.resolver.txt_lookup(query_name.clone()).await {
            Ok(txt_records) => {
                // For simplicity, we're assuming the attestation data is in a TXT record
                // In a real implementation, you might use a custom record type
                if let Some(txt) = txt_records.iter().next() {
                    let txt_data = txt.txt_data().join("");
                    return Ok(Some(AttestationRecord {
                        attestation_data: txt_data,
                    }));
                }
                Ok(None)
            },
            Err(e) => {
                // Not an error if record doesn't exist
                if e.to_string().contains("NoRecordsFound") {
                    return Ok(None);
                }
                Err(anyhow!("Failed to fetch attestation record: {}", e))
            }
        }
    }

    /// Fetches policy for a given domain
    /// We assume aDNS auto sets CNAME pointers to the service policy for every TEE instance in the service
    /// e.g. _policy.www.service.test.attested.name IN CNAME _policy.service.test.attested.name
    async fn fetch_policy(&self, domain: &str) -> Result<Option<AttestationPolicy>> {
        // Construct the name for the policy record
        let policy_query = format!("_policy.{}", domain);
        let query_name = Name::from_ascii(&policy_query)?;
        
        // Query for TXT record that contains the policy data
        match self.resolver.txt_lookup(query_name.clone()).await {
            Ok(txt_records) => {
                if let Some(txt) = txt_records.iter().next() {
                    let policy_data = txt.txt_data().join("");
                    return Ok(Some(AttestationPolicy {
                        policy_data,
                    }));
                }
                Ok(None)
            },
            Err(e) => {
                // Not an error if record doesn't exist
                if e.to_string().contains("NoRecordsFound") {
                    return Ok(None);
                }
                Err(anyhow!("Failed to fetch policy record: {}", e))
            }
        }
    }

    /// Validate an attestation record against a policy
    /// This is an abstract function that would be implemented by the caller
    fn validate_attestation(&self, attestation: &AttestationRecord, policy: &AttestationPolicy) -> bool {
        // This is a placeholder for the actual validation logic
        // In a real implementation, this would verify the attestation against the policy
        debug!("Validating attestation against policy");
        debug!("Attestation data: {}", attestation.attestation_data);
        debug!("Policy data: {}", policy.policy_data);
        
        // FIXME(adl)
        true
    }

    /// Perform DNSSEC validation for a domain
    async fn validate_dnssec(&self, domain: &str, root_domain: &str) -> Result<bool> {
        // Get the trust anchor for the domain
        let trust_anchor = self.trust_anchors.get(root_domain)
            .ok_or_else(|| anyhow!("No trust anchor for domain: {}", root_domain))?;
            
        // Create a query for the domain's DNSKEY
        let name = Name::from_ascii(domain)?;
        let query = Query::query(name.clone(), RecordType::DNSKEY);
        
        // Lookup the DNSKEY records
        let lookup = self.resolver.lookup(query, *trust_anchor).await;
        match lookup {
            Ok(response) => {
                // If we get a valid DNSSEC response, validation succeeded
                debug!("DNSSEC validation successful for {}", domain);
                Ok(true)
            },
            Err(e) => {
                // Check if this is a DNSSEC validation error
                if let hickory_resolver::error::ResolveError::Io(io_err) = &e {
                    if let Some(proto_err) = io_err.downcast_ref::<ProtoError>() {
                        if let Some(dnssec_err) = proto_err.downcast_ref::<DnssecError>() {
                            error!("DNSSEC validation failed for {}: {:?}", domain, dnssec_err);
                            return Ok(false);
                        }
                    }
                }
                // Other errors are unexpected
                Err(anyhow!("Failed to validate DNSSEC for {}: {}", domain, e))
            }
        }
    }
    
    /// Process a DNS query with attestation verification when needed
    async fn process_query(&self, query_name: &str, query_type: RecordType) -> Result<Vec<Record>> {
        let name = Name::from_ascii(query_name)?;
        
        // Check if this is a domain under one of our aDNS roots
        if let Some(root_domain) = self.is_adns_domain(query_name) {
            debug!("Domain {} is under aDNS root {}", query_name, root_domain);
            
            // Perform DNSSEC validation
            let dnssec_valid = self.validate_dnssec(query_name, &root_domain).await?;
            if !dnssec_valid {
                return Err(anyhow!("DNSSEC validation failed for {}", query_name));
            }
            
            // Fetch attestation record
            let attestation = self.fetch_attestation(query_name).await?;
            
            // Fetch policy record
            let policy = self.fetch_policy(query_name).await?;
            
            // If both attestation and policy exist, validate the attestation
            if let (Some(attest), Some(pol)) = (&attestation, &policy) {
                if !self.validate_attestation(attest, pol) {
                    return Err(anyhow!("Attestation validation failed for {}", query_name));
                }
            } else if attestation.is_some() {
                // If attestation exists but policy doesn't, warn but continue
                warn!("Attestation exists but no policy found for {}", query_name);
            }
        }
        
        // Perform the actual DNS query
        match self.resolver.lookup(name, query_type).await {
            Ok(lookup) => {
                Ok(lookup.record_iter().cloned().collect())
            },
            Err(e) => {
                Err(anyhow!("DNS lookup failed: {}", e))
            }
        }
    }
}

// DNS over HTTPS handler for JSON format
async fn handle_doh_json(
    state: Arc<RwLock<ResolverState>>,
    query: warp::query::Query<HashMap<String, String>>,
) -> Result<impl Reply, warp::Rejection> {
    // Extract query parameters
    let name = query.get("name").ok_or_else(|| warp::reject::not_found())?;
    let type_str = query.get("type").unwrap_or(&"A".to_string());
    
    // Parse query type
    let query_type = match type_str.as_str() {
        "A" => RecordType::A,
        "AAAA" => RecordType::AAAA,
        "MX" => RecordType::MX,
        "CNAME" => RecordType::CNAME,
        "TXT" => RecordType::TXT,
        "SRV" => RecordType::SRV,
        "NS" => RecordType::NS,
        _ => RecordType::A, // Default to A records
    };
    
    let state_guard = state.read().await;
    
    // Process the query
    match state_guard.process_query(name, query_type).await {
        Ok(records) => {
            // Convert records to JSON response format
            let answers: Vec<HashMap<String, String>> = records.iter().map(|r| {
                let mut answer = HashMap::new();
                answer.insert("name".to_string(), r.name().to_string());
                answer.insert("type".to_string(), r.record_type().to_string());
                answer.insert("TTL".to_string(), r.ttl().to_string());
                
                // Convert record data to string representation
                match r.data() {
                    Some(data) => { answer.insert("data".to_string(), data.to_string()); },
                    None => { answer.insert("data".to_string(), "".to_string()); }
                }
                
                answer
            }).collect();
            
            let response = serde_json::json!({
                "Status": 0,
                "TC": false,
                "RD": true,
                "RA": true,
                "AD": true, // Authenticated data - we did our own validation
                "CD": false,
                "Question": [{
                    "name": name,
                    "type": type_str
                }],
                "Answer": answers
            });
            
            Ok(warp::reply::json(&response))
        },
        Err(e) => {
            // Return error response
            let error_response = serde_json::json!({
                "Status": 2, // SERVFAIL
                "TC": false,
                "RD": true,
                "RA": true,
                "AD": false,
                "CD": false,
                "Question": [{
                    "name": name,
                    "type": type_str
                }],
                "Comment": format!("Error: {}", e)
            });
            
            Ok(warp::reply::json(&error_response))
        }
    }
}

// DNS over HTTPS handler for wire format
async fn handle_doh_wire(
    state: Arc<RwLock<ResolverState>>,
    body: Bytes,
) -> Result<impl Reply, warp::Rejection> {
    // DNS wire format handling would go here
    // For simplicity, we're not implementing the full wire format in this example
    Err(warp::reject::not_found())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logger
    env_logger::init();
    
    // Load configuration
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.json".to_string());
    
    info!("Loading configuration from {}", config_path);
    let config_str = fs::read_to_string(&config_path)
        .context(format!("Failed to read config file: {}", config_path))?;
    
    let config: ResolverConfig = serde_json::from_str(&config_str)
        .context("Failed to parse config file")?;
    
    // Create resolver state
    let state = ResolverState::new(config.clone()).await?;
    let state = Arc::new(RwLock::new(state));
    
    // Set up the server
    let bind_addr: SocketAddr = config.bind_address.parse()?;
    
    // Create routes
    let state_clone = state.clone();
    let json_route = warp::path("dns-query")
        .and(warp::get())
        .and(warp::header("accept", "application/dns-json"))
        .and(warp::any().map(move || state_clone.clone()))
        .and(warp::query::<HashMap<String, String>>())
        .and_then(handle_doh_json);
    
    let state_clone = state.clone();
    let wire_route = warp::path("dns-query")
        .and(warp::post())
        .and(warp::header("content-type", "application/dns-message"))
        .and(warp::any().map(move || state_clone.clone()))
        .and(warp::body::bytes())
        .and_then(handle_doh_wire);
    
    let routes = json_route.or(wire_route)
        .with(warp::cors().allow_any_origin());
    
    // Start the server
    info!("Starting DNS over HTTPS server on {}:{}", config.bind_address, config.port);
    
    // If TLS is configured, use HTTPS
    if let (Some(cert_file), Some(key_file)) = (&config.cert_file, &config.key_file) {
        info!("Using TLS with certificate: {}", cert_file);
        
        // Load TLS certificates
        let cert_path = Path::new(cert_file);
        let key_path = Path::new(key_file);
        
        // Start HTTPS server
        warp::serve(routes)
            .tls()
            .cert_path(cert_path)
            .key_path(key_path)
            .run(bind_addr)
            .await;
    } else {
        // Start HTTP server (not recommended for production)
        warn!("Running without TLS - not recommended for production");
        warp::serve(routes)
            .run(bind_addr)
            .await;
    }
    
    Ok(())
}
