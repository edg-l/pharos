//! M0 acceptance test.
//!
//! Runs the full conformance suite with no filter. If fixtures are absent the
//! test passes with a printed skip message. If fixtures are present and any
//! implemented category has failures the test fails.

#[test]
fn m0_acceptance() {
    let report = pharos_conformance::run(&pharos_conformance::Filter::default());

    if report.fixtures_path == "<not found>" {
        println!("m0_acceptance: spec fixtures not found — skipping conformance assertions");
        println!("  Run scripts/fetch-spec-tests.sh to download fixtures.");
        return;
    }

    println!("m0_acceptance: fixtures at {}", report.fixtures_path);
    for row in &report.rows {
        println!(
            "  {} / {} / {} — pass={} fail={} skip={} total={}",
            row.fork,
            row.category,
            row.preset,
            row.pass
                .map(|n| n.to_string())
                .unwrap_or_else(|| "-".into()),
            row.fail
                .map(|n| n.to_string())
                .unwrap_or_else(|| "-".into()),
            row.skip
                .map(|n| n.to_string())
                .unwrap_or_else(|| "-".into()),
            row.total
                .map(|n| n.to_string())
                .unwrap_or_else(|| "-".into()),
        );
    }

    if !report.failures.is_empty() {
        println!("Failures:");
        for f in &report.failures {
            println!("  {f}");
        }
    }

    assert!(
        !report.has_failures(),
        "pharos-conformance: {} test(s) failed",
        report.failures.len()
    );
}
