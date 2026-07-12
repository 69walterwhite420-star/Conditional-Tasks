//! Bakes the selected config profile (config/{testnet|mainnet}.toml, chosen by
//! CROWN_PROFILE, default testnet) into the wasm as a chain table. The frozen
//! canister has no runtime config channel; environment swap = profile swap.

use std::env;
use std::fs;
use std::path::Path;

fn value_of_opt(block: &str, key: &str) -> Option<String> {
    for line in block.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if let Some((k, v)) = line.split_once('=')
            && k.trim() == key
        {
            return Some(v.trim().trim_matches('"').to_string());
        }
    }
    None
}

fn value_of(block: &str, key: &str, context: &str) -> String {
    value_of_opt(block, key).unwrap_or_else(|| panic!("{context}: chain entry without `{key}`"))
}

fn main() {
    let profile = env::var("CROWN_PROFILE").unwrap_or_else(|_| "testnet".to_string());
    println!("cargo:rerun-if-env-changed=CROWN_PROFILE");
    let manifest = env::var("CARGO_MANIFEST_DIR").unwrap();
    let path = Path::new(&manifest).join(format!("../config/{profile}.toml"));
    println!("cargo:rerun-if-changed={}", path.display());
    let toml =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));

    // Top-level crown_index principal; the part before the first [[chain]].
    let head = toml.split("[[chain]]").next().unwrap_or_default();
    let crown_index = value_of_opt(head, "crown_index").unwrap_or_default();
    let threshold_key = value_of_opt(head, "threshold_key")
        .unwrap_or_else(|| panic!("config/{profile}.toml: no threshold_key"));
    let voting_period = value_of_opt(head, "voting_period")
        .unwrap_or_else(|| panic!("config/{profile}.toml: no voting_period"));

    let mut chains = String::new();
    for block in toml.split("[[chain]]").skip(1) {
        let context = format!("config/{profile}.toml");
        let get = |key: &str| value_of(block, key, &context);
        chains.push_str(&format!(
            "    ChainSpec {{ id: {id:?}, factory: {factory:?}, \
             domain: {domain:?}, min_gross: {min_gross} }},\n",
            id = get("id"),
            factory = get("factory"),
            domain = get("domain"),
            min_gross = get("min_gross"),
        ));
    }

    let out = Path::new(&env::var("OUT_DIR").unwrap()).join("profile.rs");
    fs::write(
        out,
        format!(
            "/// Config profile baked into this build.\n\
             pub const PROFILE: &str = {profile:?};\n\
             /// The book canister; empty until a real deploy pins it.\n\
             pub const CROWN_INDEX: &str = {crown_index:?};\n\
             /// Threshold key name of this environment.\n\
             pub const THRESHOLD_KEY: &str = {threshold_key:?};\n\
             /// Voting window in seconds; the prod value lives in mainnet.toml.\n\
             pub const VOTING_PERIOD: u64 = {voting_period};\n\
             /// Chain table from config/{profile}.toml.\n\
             pub const CHAINS: &[ChainSpec] = &[\n{chains}];\n"
        ),
    )
    .unwrap();
}
