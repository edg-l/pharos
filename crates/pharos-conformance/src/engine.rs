//! Engine API YAML conformance runner.
//!
//! Walks `execution-apis/src/engine/openrpc/methods/*.yaml`; for each
//! example pair in each V1 method's `examples:` block: spins up an axum
//! mock server on a random port, drives `EngineClient` against it, and
//! asserts the request matches the YAML params and the response parses.
//!
//! Scope: Bellatrix (Paris) V1 methods only. V2+ examples are reported
//! with skip reason `"capella+ method, scoped out of m4a"`.
//!
//! Per `D-engine-conformance-runner` (docs/m4a-plan.md Phase 5 Task 5.5).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::task::{CaseFn, CaseOutcome, CaseTask};

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use pharos_engine::{
    EngineClient, ExecutionPayloadV2, ExecutionPayloadV3, GetPayloadVersion, JwtSecret,
    NewPayloadVersion, NewPayloadWire, PayloadAttributesV3, TransitionConfigurationV1,
};
use reqwest::Url;
use serde_json::Value;
use tokio::net::TcpListener;

// ── Public result type ────────────────────────────────────────────────────────

/// Result of the engine YAML conformance suite.
pub struct CategoryResult {
    pub pass: u64,
    pub fail: u64,
    pub skip: u64,
    pub failures: Vec<String>,
    /// Reasons for skipped examples, keyed by example name.
    pub skip_reasons: HashMap<String, String>,
}

impl CategoryResult {
    fn new() -> Self {
        Self {
            pass: 0,
            fail: 0,
            skip: 0,
            failures: Vec::new(),
            skip_reasons: HashMap::new(),
        }
    }
}

// ── YAML structure models ─────────────────────────────────────────────────────

/// A parsed YAML method entry (one element of the top-level array).
struct YamlMethod {
    name: String,
    examples: Vec<YamlExample>,
}

/// A single example pair inside a method's `examples:` list.
struct YamlExample {
    name: String,
    /// JSON-serialised array of `params[*].value` objects.
    params_json: Value,
    /// JSON-serialised `result.value`.
    result_json: Value,
}

// ── Flat-pool enumerate ───────────────────────────────────────────────────────

/// Produce one `CaseTask` per Engine API YAML example in the same walk-order as
/// `run_engine_yaml_suite`. Called by the Phase 7 flat work-pool.
///
/// Engine YAML tests are preset-independent (row 83: `("engine", "yaml", "-")`).
///
/// Per Q2 in `docs/m-conf-perf-plan.md`: each example spins up its own
/// tokio Runtime + binds 127.0.0.1:0, so Runtimes are per-example (not
/// amortised) but ports are unique — correct under the flat pool.
pub fn enumerate_engine_yaml(specs_dir: &Path, row_ordinal: u32) -> Vec<CaseTask> {
    if !specs_dir.is_dir() {
        // One "failure" task mirrors the existing run_engine_yaml_suite behaviour.
        let msg = format!("engine yaml: specs dir not found: {}", specs_dir.display());
        return vec![CaseTask {
            row_ordinal,
            case_ordinal: 0,
            run: Box::new(move || CaseOutcome::Fail(msg)),
        }];
    }

    let yaml_files: Vec<_> = {
        let mut files: Vec<_> = std::fs::read_dir(specs_dir)
            .unwrap_or_else(|_| panic!("cannot read dir {}", specs_dir.display()))
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().map(|e| e == "yaml").unwrap_or(false))
            .collect();
        files.sort();
        files
    };

    let mut tasks = Vec::new();
    let mut ordinal: u32 = 0;

    for yaml_path in &yaml_files {
        let methods = match parse_yaml_methods(yaml_path) {
            Ok(m) => m,
            Err(e) => {
                let msg = format!("engine yaml: failed to parse {}: {e}", yaml_path.display());
                let case_ordinal = ordinal;
                ordinal += 1;
                tasks.push(CaseTask {
                    row_ordinal,
                    case_ordinal,
                    run: Box::new(move || CaseOutcome::Fail(msg)),
                });
                continue;
            }
        };

        for method in methods {
            let method_name: String = method.name.clone();
            let is_engine = method_name.starts_with("engine_");

            if !is_engine {
                // Non-engine methods: one skip task per example, matching run_method_examples.
                for ex in &method.examples {
                    let case_ordinal = ordinal;
                    ordinal += 1;
                    tasks.push(CaseTask {
                        row_ordinal,
                        case_ordinal,
                        run: Box::new(|| CaseOutcome::Skip),
                    });
                    let _ = ex; // suppress unused warning
                }
                continue;
            }

            const DEFERRED_V1: &[&str] = &[
                "engine_getBlobsV1",
                "engine_getPayloadBodiesByHashV1",
                "engine_getPayloadBodiesByRangeV1",
            ];
            const UNVERSIONED: &[&str] = &["engine_exchangeCapabilities"];
            const V2_IN_SCOPE: &[&str] = &["engine_newPayloadV2", "engine_forkchoiceUpdatedV2"];
            const V3_IN_SCOPE: &[&str] = &[
                "engine_newPayloadV3",
                "engine_forkchoiceUpdatedV3",
                "engine_getPayloadV3",
            ];
            const V4_PLUS: &[&str] = &[
                "engine_newPayloadV4",
                "engine_forkchoiceUpdatedV4",
                "engine_getPayloadV4",
            ];

            let is_v1 = method_name.ends_with("V1");
            let is_v2_in_scope = V2_IN_SCOPE.contains(&method_name.as_str());
            let is_v3_in_scope = V3_IN_SCOPE.contains(&method_name.as_str());
            let is_unversioned = UNVERSIONED.contains(&method_name.as_str());
            let is_deferred = DEFERRED_V1.contains(&method_name.as_str())
                || V4_PLUS.contains(&method_name.as_str());

            for ex in method.examples {
                let case_ordinal = ordinal;
                ordinal += 1;

                if is_deferred || (!is_v1 && !is_v2_in_scope && !is_v3_in_scope && !is_unversioned)
                {
                    tasks.push(CaseTask {
                        row_ordinal,
                        case_ordinal,
                        run: Box::new(|| CaseOutcome::Skip),
                    });
                    continue;
                }

                let method_name_owned = method_name.clone();
                let label = format!("{method_name}/{}", ex.name);
                let run: CaseFn =
                    Box::new(move || match run_single_example(&method_name_owned, &ex) {
                        Ok(()) => CaseOutcome::Pass,
                        Err(e) => CaseOutcome::Fail(format!("engine/{label}: {e}")),
                    });
                tasks.push(CaseTask {
                    row_ordinal,
                    case_ordinal,
                    run,
                });
            }
        }
    }

    tasks
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Run the Engine API YAML conformance suite.
///
/// `specs_dir` is the directory containing `forkchoice.yaml`, `payload.yaml`,
/// `capabilities.yaml`, etc. Typically `~/dev/execution-apis/src/engine/openrpc/methods/`.
///
/// Returns `Ok(CategoryResult)` always; errors in individual examples are
/// counted as failures, not propagated.
pub fn run_engine_yaml_suite(specs_dir: &Path) -> CategoryResult {
    let mut result = CategoryResult::new();

    if !specs_dir.is_dir() {
        result.failures.push(format!(
            "engine yaml: specs dir not found: {}",
            specs_dir.display()
        ));
        result.fail += 1;
        return result;
    }

    // Parse all YAML files in the directory.
    let yaml_files: Vec<_> = {
        let mut files: Vec<_> = std::fs::read_dir(specs_dir)
            .unwrap_or_else(|_| panic!("cannot read dir {}", specs_dir.display()))
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().map(|e| e == "yaml").unwrap_or(false))
            .collect();
        files.sort();
        files
    };

    for yaml_path in &yaml_files {
        let methods = match parse_yaml_methods(yaml_path) {
            Ok(m) => m,
            Err(e) => {
                result.fail += 1;
                result.failures.push(format!(
                    "engine yaml: failed to parse {}: {e}",
                    yaml_path.display()
                ));
                continue;
            }
        };

        for method in methods {
            run_method_examples(&method, &mut result);
        }
    }

    result
}

// ── YAML parsing ──────────────────────────────────────────────────────────────

fn parse_yaml_methods(path: &Path) -> Result<Vec<YamlMethod>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let yaml: Value = serde_yaml_ng::from_str(&text).map_err(|e| e.to_string())?;

    let arr = yaml.as_array().ok_or("expected top-level array")?;
    let mut methods = Vec::new();

    for entry in arr {
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        let examples_yaml = match entry.get("examples").and_then(Value::as_array) {
            Some(e) => e,
            None => {
                methods.push(YamlMethod {
                    name,
                    examples: vec![],
                });
                continue;
            }
        };

        let mut examples = Vec::new();
        for ex in examples_yaml {
            let ex_name = ex
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("unnamed")
                .to_string();

            // Collect params[*].value as a JSON array.
            let params_json: Value = ex
                .get("params")
                .and_then(Value::as_array)
                .map(|arr| {
                    Value::Array(arr.iter().filter_map(|p| p.get("value")).cloned().collect())
                })
                .unwrap_or(Value::Array(vec![]));

            let result_json = ex
                .get("result")
                .and_then(|r| r.get("value"))
                .cloned()
                .unwrap_or(Value::Null);

            examples.push(YamlExample {
                name: ex_name,
                params_json,
                result_json,
            });
        }

        methods.push(YamlMethod { name, examples });
    }

    Ok(methods)
}

// ── Per-method example runner ─────────────────────────────────────────────────

fn run_method_examples(method: &YamlMethod, result: &mut CategoryResult) {
    let name = &method.name;

    // Skip non-engine methods.
    if !name.starts_with("engine_") {
        result.skip += method.examples.len() as u64;
        for ex in &method.examples {
            result.skip_reasons.insert(
                format!("{name}/{}", ex.name),
                "non-engine method".to_string(),
            );
        }
        return;
    }

    // V1 methods introduced in Shanghai or later (not Bellatrix/Paris):
    // getPayloadBodies* are Shanghai V1 methods but out of scope for M6.
    // getBlobsV1 is Cancun, out of scope.
    const DEFERRED_V1: &[&str] = &[
        "engine_getBlobsV1",
        "engine_getPayloadBodiesByHashV1",
        "engine_getPayloadBodiesByRangeV1",
    ];

    // Unversioned methods (no "V1/V2" suffix) in scope.
    const UNVERSIONED: &[&str] = &["engine_exchangeCapabilities"];

    // V2 methods in scope for M6 (Capella / Shanghai).
    const V2_IN_SCOPE: &[&str] = &["engine_newPayloadV2", "engine_forkchoiceUpdatedV2"];

    // V3 methods in scope for M10-Deneb (Cancun).
    const V3_IN_SCOPE: &[&str] = &[
        "engine_newPayloadV3",
        "engine_forkchoiceUpdatedV3",
        "engine_getPayloadV3",
    ];

    // V4+ methods not yet in scope (Prague+).
    const V4_PLUS: &[&str] = &[
        "engine_newPayloadV4",
        "engine_forkchoiceUpdatedV4",
        "engine_getPayloadV4",
    ];

    let is_v1 = name.ends_with("V1");
    let is_v2_in_scope = V2_IN_SCOPE.contains(&name.as_str());
    let is_v3_in_scope = V3_IN_SCOPE.contains(&name.as_str());
    let is_unversioned = UNVERSIONED.contains(&name.as_str());
    let is_deferred = DEFERRED_V1.contains(&name.as_str()) || V4_PLUS.contains(&name.as_str());

    for ex in &method.examples {
        let label = format!("{name}/{}", ex.name);

        // Skip deferred/out-of-scope methods.
        if is_deferred || (!is_v1 && !is_v2_in_scope && !is_v3_in_scope && !is_unversioned) {
            result.skip += 1;
            result.skip_reasons.insert(
                label,
                "method not in scope for current milestone".to_string(),
            );
            continue;
        }

        match run_single_example(name, ex) {
            Ok(()) => result.pass += 1,
            Err(e) => {
                result.fail += 1;
                result.failures.push(format!("engine/{label}: {e}"));
            }
        }
    }
}

// ── Mock server state ─────────────────────────────────────────────────────────

#[derive(Clone)]
struct MockState {
    /// The JSON-RPC result value to return.
    result: Arc<Value>,
    /// Captured request body (set on first request).
    captured: Arc<Mutex<Option<Value>>>,
}

async fn mock_handler(
    State(state): State<MockState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    // Verify Bearer token is present (any value accepted).
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !auth.starts_with("Bearer ") {
        return (StatusCode::UNAUTHORIZED, "missing bearer token").into_response();
    }

    // Parse and store the request.
    if let Ok(parsed) = serde_json::from_slice::<Value>(&body) {
        *state.captured.lock().unwrap() = Some(parsed.clone());

        let id = parsed.get("id").cloned().unwrap_or(Value::Number(1.into()));
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": *state.result,
        });

        return (StatusCode::OK, axum::response::Json(response)).into_response();
    }

    (StatusCode::BAD_REQUEST, "bad json").into_response()
}

// ── Single example runner ─────────────────────────────────────────────────────

fn run_single_example(method_name: &str, ex: &YamlExample) -> Result<(), String> {
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;

    rt.block_on(async {
        // Spin up mock server.
        let captured = Arc::new(Mutex::new(None::<Value>));
        let result_val = Arc::new(ex.result_json.clone());

        let state = MockState {
            result: Arc::clone(&result_val),
            captured: Arc::clone(&captured),
        };

        let app = Router::new()
            .route("/", post(mock_handler))
            .with_state(state);

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| e.to_string())?;
        let addr: SocketAddr = listener.local_addr().map_err(|e| e.to_string())?;

        let server = axum::serve(listener, app);
        // Run server in background; abort on drop via the JoinHandle.
        let handle = tokio::spawn(server.into_future());

        // Build EngineClient pointing at the mock.
        let url = Url::parse(&format!("http://{addr}")).map_err(|e| e.to_string())?;
        let jwt = JwtSecret::from_bytes([0u8; 32]);
        let client = EngineClient::new(url, jwt).map_err(|e| e.to_string())?;

        // Dispatch based on method name; returns the parsed+re-serialised response.
        let got_response = dispatch_engine_call(&client, method_name, &ex.params_json).await;

        // Abort mock server.
        handle.abort();

        let got_response = got_response?;

        // Verify captured request had correct method name and matching params.
        let req = captured
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| "mock server received no request".to_string())?;
        let got_method = req.get("method").and_then(Value::as_str).unwrap_or("");
        if got_method != method_name {
            return Err(format!("expected method {method_name}, got {got_method}"));
        }

        // Assert the params sent by EngineClient match the YAML example params.
        // Structural comparison on serde_json::Value handles key-order differences.
        let got_params = req.get("params").cloned().unwrap_or(Value::Array(vec![]));
        // getPayload* take a single payload-id param. The upstream example value
        // is QUANTITY-trimmed (odd-length hex) which cannot round-trip byte-exact
        // through the 8-byte `PayloadIdV1` DATA type, so compare it semantically.
        let params_match = if method_name.starts_with("engine_getPayload") {
            let got_id = params_to_payload_id(got_params.as_array().and_then(|a| a.first()));
            let want_id = params_to_payload_id(ex.params_json.as_array().and_then(|a| a.first()));
            got_id == want_id
        } else {
            got_params == ex.params_json
        };
        if !params_match {
            return Err(format!(
                "params mismatch for {method_name}:\n  want: {}\n   got: {}",
                serde_json::to_string(&ex.params_json).unwrap_or_default(),
                serde_json::to_string(&got_params).unwrap_or_default(),
            ));
        }

        // Assert the response parsed by EngineClient matches the YAML result value.
        // For array responses (e.g. engine_exchangeCapabilities) compare as sorted
        // sets because the wire order is unspecified.
        if !json_values_equivalent(&got_response, &ex.result_json) {
            return Err(format!(
                "response shape mismatch:\n  want: {}\n   got: {}",
                serde_json::to_string(&ex.result_json).unwrap_or_default(),
                serde_json::to_string(&got_response).unwrap_or_default(),
            ));
        }

        Ok(())
    })
}

/// Compare two `serde_json::Value`s for logical equivalence.
///
/// - **String arrays**: compared order-insensitively (sorted) because some
///   Engine API methods (e.g. `engine_exchangeCapabilities`) return an
///   unordered list of method names.
/// - **Non-string arrays** (e.g. `ExecutionPayload.transactions`): compared
///   positionally, element-by-element, so wrong transaction order is not
///   silently masked.
/// - **Objects**: recurse into each key-value pair; key order does not matter.
/// - **Scalars / null / bool**: use standard `==` equality.
fn json_values_equivalent(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Array(av), Value::Array(bv)) => {
            // Order-insensitive only for arrays of strings (method-name lists).
            // Ordered arrays (e.g., ExecutionPayload.transactions) must compare positionally.
            let all_strings = av.iter().all(|v| v.is_string()) && bv.iter().all(|v| v.is_string());
            if all_strings {
                let mut sa: Vec<&str> = av.iter().filter_map(|v| v.as_str()).collect();
                let mut sb: Vec<&str> = bv.iter().filter_map(|v| v.as_str()).collect();
                sa.sort();
                sb.sort();
                sa == sb
            } else {
                av.len() == bv.len()
                    && av
                        .iter()
                        .zip(bv.iter())
                        .all(|(x, y)| json_values_equivalent(x, y))
            }
        }
        (Value::Object(ao), Value::Object(bo)) => {
            ao.len() == bo.len()
                && ao.iter().all(|(k, v)| {
                    bo.get(k)
                        .map(|bv| json_values_equivalent(v, bv))
                        .unwrap_or(false)
                })
        }
        _ => a == b,
    }
}

// ── Engine call dispatcher ────────────────────────────────────────────────────

async fn dispatch_engine_call(
    client: &EngineClient,
    method: &str,
    _params: &Value,
) -> Result<Value, String> {
    match method {
        "engine_newPayloadV1" => {
            let payload = params_to_execution_payload_v1(_params.get(0));
            let status = client
                .new_payload(NewPayloadVersion::V1, NewPayloadWire::V1(payload))
                .await
                .map_err(|e| e.to_string())?;
            serde_json::to_value(status).map_err(|e| e.to_string())
        }
        "engine_newPayloadV2" => {
            let payload = params_to_execution_payload_v2(_params.get(0));
            let status = client
                .new_payload(NewPayloadVersion::V2, NewPayloadWire::V2(payload))
                .await
                .map_err(|e| e.to_string())?;
            serde_json::to_value(status).map_err(|e| e.to_string())
        }
        "engine_forkchoiceUpdatedV1" => {
            let state = params_to_forkchoice_state(_params.get(0));
            let attrs = _params.get(1).and_then(|v| {
                if v.is_null() {
                    None
                } else {
                    params_to_payload_attrs(v).ok()
                }
            });
            let fcu_response = client
                .forkchoice_updated_v1(state, attrs)
                .await
                .map_err(|e| e.to_string())?;
            serde_json::to_value(fcu_response).map_err(|e| e.to_string())
        }
        "engine_forkchoiceUpdatedV2" => {
            let state = params_to_forkchoice_state(_params.get(0));
            let attrs = _params.get(1).and_then(|v| {
                if v.is_null() {
                    None
                } else {
                    params_to_payload_attrs_v2(v).ok()
                }
            });
            let fcu_response = client
                .forkchoice_updated_v2(state, attrs)
                .await
                .map_err(|e| e.to_string())?;
            serde_json::to_value(fcu_response).map_err(|e| e.to_string())
        }
        "engine_getPayloadV1" => {
            let id = params_to_payload_id(_params.get(0));
            let payload = client
                .get_payload(GetPayloadVersion::V1, id)
                .await
                .map_err(|e| e.to_string())?;
            serde_json::to_value(payload).map_err(|e| e.to_string())
        }
        "engine_exchangeCapabilities" => {
            // Extract the capabilities list from params[0] (array of strings).
            let methods_owned: Vec<String> = _params
                .get(0)
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            let methods_refs: Vec<&str> = methods_owned.iter().map(String::as_str).collect();
            let capabilities = client
                .exchange_capabilities(&methods_refs)
                .await
                .map_err(|e| e.to_string())?;
            // Convert HashSet to a sorted Vec for deterministic serialisation.
            let mut sorted: Vec<&String> = capabilities.iter().collect();
            sorted.sort();
            serde_json::to_value(sorted).map_err(|e| e.to_string())
        }
        "engine_newPayloadV3" => {
            let payload = params_to_execution_payload_v3(_params.get(0));
            // params[1]: expectedBlobVersionedHashes — array of hex hash strings.
            let versioned_hashes: Vec<String> = _params
                .get(1)
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            // params[2]: parentBeaconBlockRoot — hex hash string.
            let parent_beacon_block_root = _params
                .get(2)
                .and_then(Value::as_str)
                .unwrap_or("0x0000000000000000000000000000000000000000000000000000000000000000")
                .to_string();
            let status = client
                .new_payload(
                    NewPayloadVersion::V3,
                    NewPayloadWire::V3 {
                        payload,
                        versioned_hashes,
                        parent_beacon_block_root,
                    },
                )
                .await
                .map_err(|e| e.to_string())?;
            serde_json::to_value(status).map_err(|e| e.to_string())
        }
        "engine_forkchoiceUpdatedV3" => {
            let state = params_to_forkchoice_state(_params.get(0));
            let attrs = _params.get(1).and_then(|v| {
                if v.is_null() {
                    None
                } else {
                    params_to_payload_attrs_v3(v).ok()
                }
            });
            let fcu_response = client
                .forkchoice_updated_v3(state, attrs)
                .await
                .map_err(|e| e.to_string())?;
            serde_json::to_value(fcu_response).map_err(|e| e.to_string())
        }
        "engine_getPayloadV3" => {
            let id = params_to_payload_id(_params.get(0));
            let response = client.get_payload_v3(id).await.map_err(|e| e.to_string())?;
            serde_json::to_value(response).map_err(|e| e.to_string())
        }
        "engine_exchangeTransitionConfigurationV1" => {
            let config = params_to_transition_config(_params.get(0));
            let transition_config = client
                .exchange_transition_configuration(config)
                .await
                .map_err(|e| e.to_string())?;
            serde_json::to_value(transition_config).map_err(|e| e.to_string())
        }
        _ => {
            // Unknown V1 method — this should not happen for in-scope methods.
            Err(format!("unhandled engine method: {method}"))
        }
    }
}

// ── Param extraction helpers ──────────────────────────────────────────────────

fn params_to_execution_payload_v1(v: Option<&Value>) -> pharos_engine::ExecutionPayloadV1 {
    let v = match v {
        Some(v) => v,
        None => {
            return pharos_engine::ExecutionPayloadV1 {
                parent_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
                fee_recipient: "0x0000000000000000000000000000000000000000".into(),
                state_root: "0x0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
                receipts_root: "0x0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
                logs_bloom: "0x00".into(),
                prev_randao: "0x0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
                block_number: "0x0".into(),
                gas_limit: "0x0".into(),
                gas_used: "0x0".into(),
                timestamp: "0x0".into(),
                extra_data: "0x".into(),
                base_fee_per_gas: "0x0".into(),
                block_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
                transactions: vec![],
            };
        }
    };
    serde_json::from_value(v.clone()).unwrap_or_else(|_| pharos_engine::ExecutionPayloadV1 {
        parent_hash: str_field(v, "parentHash"),
        fee_recipient: str_field(v, "feeRecipient"),
        state_root: str_field(v, "stateRoot"),
        receipts_root: str_field(v, "receiptsRoot"),
        logs_bloom: str_field(v, "logsBloom"),
        prev_randao: str_field(v, "prevRandao"),
        block_number: str_field(v, "blockNumber"),
        gas_limit: str_field(v, "gasLimit"),
        gas_used: str_field(v, "gasUsed"),
        timestamp: str_field(v, "timestamp"),
        extra_data: str_field(v, "extraData"),
        base_fee_per_gas: str_field(v, "baseFeePerGas"),
        block_hash: str_field(v, "blockHash"),
        transactions: vec![],
    })
}

fn params_to_execution_payload_v2(v: Option<&Value>) -> ExecutionPayloadV2 {
    use pharos_engine::WithdrawalV1;
    let v = match v {
        Some(v) => v,
        None => {
            return ExecutionPayloadV2 {
                parent_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
                fee_recipient: "0x0000000000000000000000000000000000000000".into(),
                state_root: "0x0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
                receipts_root: "0x0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
                logs_bloom: "0x00".into(),
                prev_randao: "0x0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
                block_number: "0x0".into(),
                gas_limit: "0x0".into(),
                gas_used: "0x0".into(),
                timestamp: "0x0".into(),
                extra_data: "0x".into(),
                base_fee_per_gas: "0x0".into(),
                block_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
                transactions: vec![],
                withdrawals: vec![],
            };
        }
    };
    serde_json::from_value(v.clone()).unwrap_or_else(|_| ExecutionPayloadV2 {
        parent_hash: str_field(v, "parentHash"),
        fee_recipient: str_field(v, "feeRecipient"),
        state_root: str_field(v, "stateRoot"),
        receipts_root: str_field(v, "receiptsRoot"),
        logs_bloom: str_field(v, "logsBloom"),
        prev_randao: str_field(v, "prevRandao"),
        block_number: str_field(v, "blockNumber"),
        gas_limit: str_field(v, "gasLimit"),
        gas_used: str_field(v, "gasUsed"),
        timestamp: str_field(v, "timestamp"),
        extra_data: str_field(v, "extraData"),
        base_fee_per_gas: str_field(v, "baseFeePerGas"),
        block_hash: str_field(v, "blockHash"),
        transactions: vec![],
        withdrawals: v
            .get("withdrawals")
            .and_then(|w| serde_json::from_value::<Vec<WithdrawalV1>>(w.clone()).ok())
            .unwrap_or_default(),
    })
}

fn params_to_forkchoice_state(v: Option<&Value>) -> pharos_engine::ForkchoiceStateV1 {
    let zero = "0x0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let v = match v {
        Some(v) => v,
        None => {
            return pharos_engine::ForkchoiceStateV1 {
                head_block_hash: zero.clone(),
                safe_block_hash: zero.clone(),
                finalized_block_hash: zero,
            };
        }
    };
    serde_json::from_value(v.clone()).unwrap_or_else(|_| pharos_engine::ForkchoiceStateV1 {
        head_block_hash: str_field(v, "headBlockHash"),
        safe_block_hash: str_field(v, "safeBlockHash"),
        finalized_block_hash: str_field(v, "finalizedBlockHash"),
    })
}

fn params_to_payload_attrs(v: &Value) -> Result<pharos_engine::PayloadAttributesV1, String> {
    serde_json::from_value(v.clone()).map_err(|e| e.to_string())
}

fn params_to_payload_attrs_v2(v: &Value) -> Result<pharos_engine::PayloadAttributesV2, String> {
    serde_json::from_value(v.clone()).map_err(|e| e.to_string())
}

fn params_to_execution_payload_v3(v: Option<&Value>) -> ExecutionPayloadV3 {
    use pharos_engine::WithdrawalV1;
    let v = match v {
        Some(v) => v,
        None => {
            return ExecutionPayloadV3 {
                parent_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
                fee_recipient: "0x0000000000000000000000000000000000000000".into(),
                state_root: "0x0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
                receipts_root: "0x0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
                logs_bloom: "0x00".into(),
                prev_randao: "0x0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
                block_number: "0x0".into(),
                gas_limit: "0x0".into(),
                gas_used: "0x0".into(),
                timestamp: "0x0".into(),
                extra_data: "0x".into(),
                base_fee_per_gas: "0x0".into(),
                block_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
                transactions: vec![],
                withdrawals: vec![],
                blob_gas_used: "0x0".into(),
                excess_blob_gas: "0x0".into(),
            };
        }
    };
    serde_json::from_value(v.clone()).unwrap_or_else(|_| ExecutionPayloadV3 {
        parent_hash: str_field(v, "parentHash"),
        fee_recipient: str_field(v, "feeRecipient"),
        state_root: str_field(v, "stateRoot"),
        receipts_root: str_field(v, "receiptsRoot"),
        logs_bloom: str_field(v, "logsBloom"),
        prev_randao: str_field(v, "prevRandao"),
        block_number: str_field(v, "blockNumber"),
        gas_limit: str_field(v, "gasLimit"),
        gas_used: str_field(v, "gasUsed"),
        timestamp: str_field(v, "timestamp"),
        extra_data: str_field(v, "extraData"),
        base_fee_per_gas: str_field(v, "baseFeePerGas"),
        block_hash: str_field(v, "blockHash"),
        transactions: v
            .get("transactions")
            .and_then(|t| serde_json::from_value::<Vec<String>>(t.clone()).ok())
            .unwrap_or_default(),
        withdrawals: v
            .get("withdrawals")
            .and_then(|w| serde_json::from_value::<Vec<WithdrawalV1>>(w.clone()).ok())
            .unwrap_or_default(),
        blob_gas_used: str_field(v, "blobGasUsed"),
        excess_blob_gas: str_field(v, "excessBlobGas"),
    })
}

fn params_to_payload_attrs_v3(v: &Value) -> Result<PayloadAttributesV3, String> {
    serde_json::from_value(v.clone()).map_err(|e| e.to_string())
}

fn params_to_payload_id(v: Option<&Value>) -> pharos_engine::PayloadIdV1 {
    let s = v.and_then(Value::as_str).unwrap_or("0x0000000000000000");
    // Upstream execution-apis examples write payload ids QUANTITY-style (leading
    // zeros trimmed, sometimes odd length, e.g. `0x0000000038fa5dd`), but
    // `PayloadIdV1` is a fixed 8-byte DATA value. Strip quotes/`0x`, left-pad to
    // 16 hex chars, then decode — robust to the malformed-but-canonical example.
    let hex = s.trim_matches('"').trim_start_matches("0x");
    let padded = format!("{hex:0>16}");
    let mut bytes = [0u8; 8];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&padded[i * 2..i * 2 + 2], 16).unwrap_or(0);
    }
    pharos_engine::PayloadIdV1(bytes)
}

fn params_to_transition_config(v: Option<&Value>) -> TransitionConfigurationV1 {
    let zero_hash =
        "0x0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let v = match v {
        Some(v) => v,
        None => {
            return TransitionConfigurationV1 {
                terminal_total_difficulty: "0x0".to_string(),
                terminal_block_hash: zero_hash,
                terminal_block_number: "0x0".to_string(),
            };
        }
    };
    serde_json::from_value(v.clone()).unwrap_or_else(|_| TransitionConfigurationV1 {
        terminal_total_difficulty: str_field(v, "terminalTotalDifficulty"),
        terminal_block_hash: str_field(v, "terminalBlockHash"),
        terminal_block_number: str_field(v, "terminalBlockNumber"),
    })
}

fn str_field(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::CaseOutcome;

    /// Resolve the engine YAML specs dir the same way `lib.rs::dirs_engine_yaml` does.
    fn engine_specs_dir() -> std::path::PathBuf {
        if let Ok(dir) = std::env::var("EXECUTION_APIS_DIR") {
            let p = std::path::Path::new(&dir).join("src/engine/openrpc/methods");
            if p.is_dir() {
                return p;
            }
        }
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
        std::path::PathBuf::from(home).join("dev/execution-apis/src/engine/openrpc/methods")
    }

    #[test]
    fn enumerate_engine_yaml_parity() {
        let specs_dir = engine_specs_dir();
        if !specs_dir.is_dir() {
            return; // skip cleanly when execution-apis not present
        }
        let run_result = run_engine_yaml_suite(&specs_dir);
        let tasks = enumerate_engine_yaml(&specs_dir, 83);
        let mut ep = 0u64;
        let mut ef = 0u64;
        let mut es = 0u64;
        for task in tasks {
            match (task.run)() {
                CaseOutcome::Pass => ep += 1,
                CaseOutcome::Fail(_) => ef += 1,
                CaseOutcome::Skip => es += 1,
            }
        }
        assert_eq!(
            (ep, ef, es),
            (run_result.pass, run_result.fail, run_result.skip),
            "enumerate_engine_yaml counts differ from run_engine_yaml_suite"
        );
    }
}
