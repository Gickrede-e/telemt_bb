//! Tests for SNI-keyed ALPN profile selection.
//!
//! Refs docs/PERFORMANCE_AND_ANTIDETECT.ru.md §2.6.

use super::*;

fn s(v: &str) -> String {
    v.to_string()
}

fn b(v: &str) -> Vec<u8> {
    v.as_bytes().to_vec()
}

#[test]
fn empty_profiles_returns_none() {
    let alpn = vec![b("h2"), b("http/1.1")];
    assert_eq!(select_alpn_echo(&alpn, Some("any.host"), &[], 0), None);
}

#[test]
fn empty_client_alpn_returns_none() {
    let profiles = vec![vec![s("h2"), s("http/1.1")]];
    assert_eq!(select_alpn_echo(&[], Some("any.host"), &profiles, 0), None);
}

#[test]
fn single_profile_picks_first_intersection() {
    let alpn = vec![b("http/1.1"), b("h2")];
    let profiles = vec![vec![s("h2"), s("http/1.1")]];
    let pick = select_alpn_echo(&alpn, Some("a.com"), &profiles, 0);
    assert_eq!(pick, Some(b("h2")));
}

#[test]
fn intersection_uses_profile_order_not_client_order() {
    // Client offers [http/1.1, h2]; profile order = [h2, http/1.1].
    // Selection must prefer h2 because it appears first in the profile.
    let alpn = vec![b("http/1.1"), b("h2")];
    let profiles = vec![vec![s("h2"), s("http/1.1")]];
    let pick = select_alpn_echo(&alpn, Some("ord.test"), &profiles, 0);
    assert_eq!(pick, Some(b("h2")));
}

#[test]
fn deterministic_for_same_sni_and_bucket() {
    let alpn = vec![b("h2"), b("http/1.1")];
    let profiles = vec![vec![s("h2")], vec![s("http/1.1")]];
    let a = select_alpn_echo(&alpn, Some("stable.host"), &profiles, 86_400);
    for _ in 0..50 {
        let b_pick = select_alpn_echo(&alpn, Some("stable.host"), &profiles, 86_400);
        assert_eq!(a, b_pick);
    }
}

#[test]
fn distribution_across_many_snis_covers_all_profiles() {
    let alpn = vec![b("h2"), b("http/1.1")];
    let profiles = vec![vec![s("h2")], vec![s("http/1.1")]];
    let mut h2 = 0u32;
    let mut h11 = 0u32;
    for i in 0u32..1000 {
        let sni = format!("host-{}.example", i);
        let pick =
            select_alpn_echo(&alpn, Some(&sni), &profiles, 0).expect("intersection non-empty");
        if pick == b("h2") {
            h2 += 1;
        } else if pick == b("http/1.1") {
            h11 += 1;
        }
    }
    // Roughly 50/50; allow generous slack.
    assert!(
        h2 > 350 && h11 > 350,
        "profile distribution unbalanced: h2={}, http1.1={}",
        h2,
        h11
    );
}

#[test]
fn returns_none_when_intersection_is_empty() {
    let alpn = vec![b("http/1.0")];
    let profiles = vec![vec![s("h2"), s("http/1.1")]];
    let pick = select_alpn_echo(&alpn, Some("empty.intersection"), &profiles, 0);
    assert_eq!(pick, None);
}

#[test]
fn rare_protocol_can_be_selected_when_in_both_profile_and_client() {
    let alpn = vec![b("h2"), b("http/1.1"), b("h2c")];
    let profiles = vec![vec![s("h2c"), s("h2")]];
    let pick = select_alpn_echo(&alpn, Some("rare.proto.test"), &profiles, 0);
    assert_eq!(pick, Some(b("h2c")));
}

#[test]
fn bucket_zero_locks_profile_per_sni_across_time() {
    // With bucket_secs = 0, the time component is fixed at 0 so a given SNI
    // sees a stable profile choice even across long simulated time windows.
    let alpn = vec![b("h2"), b("http/1.1")];
    let profiles = vec![vec![s("h2")], vec![s("http/1.1")]];
    let a = select_alpn_echo(&alpn, Some("lock.host"), &profiles, 0);
    std::thread::sleep(std::time::Duration::from_millis(10));
    let b_pick = select_alpn_echo(&alpn, Some("lock.host"), &profiles, 0);
    assert_eq!(a, b_pick);
}

#[test]
fn missing_sni_still_returns_consistent_pick() {
    let alpn = vec![b("h2"), b("http/1.1")];
    let profiles = vec![vec![s("h2"), s("http/1.1")]];
    let a = select_alpn_echo(&alpn, None, &profiles, 0);
    let b_pick = select_alpn_echo(&alpn, None, &profiles, 0);
    assert_eq!(a, b_pick);
    assert_eq!(a, Some(b("h2")));
}
