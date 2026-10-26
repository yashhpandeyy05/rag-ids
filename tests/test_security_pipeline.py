"""
RAG-IDS Security Evaluation & Pipeline Integrity Test Suite
Verifies:
1. Preservation of existing IDS functionality (detector, launch, results, meta).
2. Server-side security authentication & authorization enforcement (401 on unauthorized).
3. Document-Level Membership Inference Attack (DL-MIA) execution and metric calculation.
4. Knowledge-Base Data Poisoning attack (RAGuard, baseline vs. poisoned, cleanup).
5. Retrieved-Content Leakage attack (canaries, prompt injection, isolation, cleanup).
6. Production Knowledge Base integrity (zero contamination of threat_kb).
"""

from fastapi.testclient import TestClient
from web.server import app, SECURITY_AUTH_KEY
import chromadb
from src.config import CHROMA_DB_DIR
from src.retriever import COLLECTION as COLLECTION_NAME


client = TestClient(app)


def test_existing_ids_meta_and_launch():
    """Verify existing IDS endpoints function normally."""
    meta_resp = client.get("/api/meta")
    assert meta_resp.status_code == 200
    meta = meta_resp.json()
    assert "dataset_name" in meta
    assert "security_auth_token" in meta
    assert meta["security_auth_token"] == SECURITY_AUTH_KEY
    assert len(meta["scenarios"]) > 0

    # Test Launch endpoint (XGBoost detector)
    launch_resp = client.post("/api/launch", json={"mystery": True})
    assert launch_resp.status_code == 200
    launch_data = launch_resp.json()
    assert "sample_id" in launch_data
    assert "detection" in launch_data
    assert "label" in launch_data["detection"]
    assert "confidence" in launch_data["detection"]
    assert len(launch_data["detection"]["features"]) > 0


def test_existing_results_endpoint():
    """Verify model results endpoint functions normally."""
    res_resp = client.get("/api/results")
    assert res_resp.status_code == 200
    res_data = res_resp.json()
    assert "metrics" in res_data
    assert "macro_f1" in res_data["metrics"]["test"]
    assert len(res_data["per_label"]) > 0


def test_security_auth_enforcement():
    """Verify endpoints reject unauthenticated or incorrectly authenticated requests."""
    # 1. No auth header -> 401
    resp = client.post("/api/security/membership-inference", json={"sample_size": 3})
    assert resp.status_code == 401
    assert "Unauthorized" in resp.json()["detail"]

    # 2. Invalid auth header -> 401
    resp = client.post(
        "/api/security/membership-inference",
        json={"sample_size": 3},
        headers={"X-Security-Key": "invalid-wrong-key-12345"}
    )
    assert resp.status_code == 401

    # 3. Valid auth key via X-Security-Key -> Accepted (200)
    valid_headers = {"X-Security-Key": SECURITY_AUTH_KEY}
    meta_sec = client.get("/api/security/meta", headers=valid_headers)
    assert meta_sec.status_code == 200
    assert len(meta_sec.json()["attacks"]) == 3


def test_membership_inference_attack():
    """Verify Document-Level Membership Inference evaluates real observables and calculates metrics."""
    valid_headers = {"X-Security-Key": SECURITY_AUTH_KEY}
    payload = {"sample_size": 4, "decision_threshold": None}
    resp = client.post("/api/security/membership-inference", json=payload, headers=valid_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["attack_type"] == "membership_inference"
    assert data["status"] in ["PASSED", "FAILED", "INCONCLUSIVE"]
    assert "verdict_explanation" in data

    metrics = data["metrics"]
    assert 0.0 <= metrics["roc_auc"] <= 1.0
    assert 0.0 <= metrics["precision"] <= 1.0
    assert 0.0 <= metrics["recall"] <= 1.0
    assert 0.0 <= metrics["f1_score"] <= 1.0
    assert 0.0 <= metrics["accuracy"] <= 1.0
    assert metrics["true_positives"] + metrics["false_negatives"] == 4
    assert metrics["true_negatives"] + metrics["false_positives"] == 4

    evidence = data["evidence"]
    assert len(evidence) == 8  # 4 members + 4 controls
    for item in evidence:
        assert "cosine_similarity" in item
        assert "containment_score" in item
        assert "membership_score" in item
        assert "predicted_member" in item
        assert item["cosine_similarity"] > 0.0


def test_data_poisoning_attack():
    """Verify Data Poisoning tests baseline vs. post-poisoning retrieval and verifies safe cleanup."""
    valid_headers = {"X-Security-Key": SECURITY_AUTH_KEY}
    payload = {"trigger_phrase": "[TEST-TRIGGER-CYBER]", "num_queries": 2}
    resp = client.post("/api/security/data-poisoning", json=payload, headers=valid_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["attack_type"] == "data_poisoning"
    assert data["status"] in ["PASSED", "FAILED", "INCONCLUSIVE"]
    
    metrics = data["metrics"]
    assert 0.0 <= metrics["attack_success_rate_ASR"] <= 1.0
    assert 0.0 <= metrics["poison_retrieval_success_rate_RSR"] <= 1.0
    assert metrics["baseline_compromise_rate"] == 0.0
    assert metrics["poisoned_documents_removed"] == metrics["poisoned_documents_injected"]

    assert data["configuration"]["cleanup_verified"] is True
    assert len(data["evidence"]) == 2
    assert len(data["raguard_analysis"]) == 2


def test_retrieved_content_leakage_attack():
    """Verify Retrieved-Content Leakage tests canaries, prompt injection, and cleans up."""
    valid_headers = {"X-Security-Key": SECURITY_AUTH_KEY}
    payload = {"num_canaries": 2}
    resp = client.post("/api/security/retrieved-leakage", json=payload, headers=valid_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["attack_type"] == "retrieved_leakage"
    assert data["status"] in ["PASSED", "FAILED", "INCONCLUSIVE"]

    metrics = data["metrics"]
    assert 0.0 <= metrics["retrieval_leakage_rate"] <= 1.0
    assert 0.0 <= metrics["generation_leakage_rate"] <= 1.0
    assert 0.0 <= metrics["access_control_violation_rate"] <= 1.0
    assert metrics["canaries_cleaned"] == metrics["canaries_injected"]
    assert data["configuration"]["cleanup_verified"] is True


def test_production_threat_kb_integrity():
    """Verify production Chroma collection 'threat_kb' was never modified or contaminated by attacks."""
    chroma_client = chromadb.PersistentClient(path=str(CHROMA_DB_DIR))
    prod_col = chroma_client.get_collection(COLLECTION_NAME)
    count = prod_col.count()
    assert count == 2339, f"Production knowledge base chunk count altered! Expected 2339, found {count}"

    # Verify no test artifacts exist in production
    res = prod_col.get(where={"doc_type": "canary_secret"})
    assert len(res["ids"]) == 0
    res_poison = prod_col.get(where={"doc_type": "poisoned_mitre_mitigation"})
    assert len(res_poison["ids"]) == 0
    print("ALL PRODUCTION INTEGRITY CHECKS PASSED: threat_kb has exactly 2339 chunks and 0 test artifacts.")


def test_custom_dataset_upload_and_simulation():
    """Verify custom dataset upload, parsing, and multi-attack simulation."""
    valid_headers = {"X-Security-Key": SECURITY_AUTH_KEY}

    # 1. Test CSV Upload
    csv_content = b"doc_id,title,text,is_member\nCUSTOM_1,Port Scanning T1046,Adversaries scan open ports to discover active services,1\nCUSTOM_2,Modbus Injection,Modbus lacks authentication and allows command injection,0"
    files = {"file": ("custom_threats.csv", csv_content, "text/csv")}
    upload_resp = client.post("/api/security/upload-dataset", files=files, headers=valid_headers)
    assert upload_resp.status_code == 200
    up_data = upload_resp.json()
    assert up_data["filename"] == "custom_threats.csv"
    assert up_data["count"] == 2
    docs = up_data["documents"]
    assert docs[0]["doc_id"] == "CUSTOM_1"
    assert docs[0]["is_member"] is True
    assert docs[1]["is_member"] is False

    # 2. Test Preset Loading
    preset_resp = client.get("/api/security/sample-preset?preset=poison_payloads", headers=valid_headers)
    assert preset_resp.status_code == 200
    preset_data = preset_resp.json()
    assert preset_data["count"] >= 2
    poison_docs = preset_data["documents"]

    # 3. Test Custom MIA Simulation
    sim_mia = client.post("/api/security/simulate-custom", json={
        "attack_type": "membership_inference",
        "documents": docs,
        "decision_threshold": 0.75
    }, headers=valid_headers)
    assert sim_mia.status_code == 200
    mia_res = sim_mia.json()
    assert mia_res["attack_type"] == "membership_inference"
    assert "metrics" in mia_res
    assert len(mia_res["evidence"]) >= 2
    assert mia_res["evidence"][0]["cosine_similarity"] > 0.0

    # 4. Test Custom Poisoning Simulation
    sim_poison = client.post("/api/security/simulate-custom", json={
        "attack_type": "data_poisoning",
        "documents": poison_docs,
        "trigger_phrase": "[TEST-CUSTOM-TRIGGER]"
    }, headers=valid_headers)
    assert sim_poison.status_code == 200
    poison_res = sim_poison.json()
    assert poison_res["attack_type"] == "data_poisoning"
    assert 0.0 <= poison_res["metrics"]["attack_success_rate_ASR"] <= 1.0
    assert poison_res["configuration"]["cleanup_verified"] is True

    # 5. Test Custom Leakage Simulation
    sim_leak = client.post("/api/security/simulate-custom", json={
        "attack_type": "retrieved_leakage",
        "documents": docs,
        "canary_token": "CANARY-SECRET-TEST-99"
    }, headers=valid_headers)
    assert sim_leak.status_code == 200
    leak_res = sim_leak.json()
    assert leak_res["attack_type"] == "retrieved_leakage"
    assert 0.0 <= leak_res["metrics"]["retrieval_leakage_rate"] <= 1.0
    assert leak_res["configuration"]["cleanup_verified"] is True
    print("PASS: test_custom_dataset_upload_and_simulation")


if __name__ == "__main__":
    print("Running test_existing_ids_meta_and_launch...")
    test_existing_ids_meta_and_launch()
    print("PASS: test_existing_ids_meta_and_launch")

    print("Running test_existing_results_endpoint...")
    test_existing_results_endpoint()
    print("PASS: test_existing_results_endpoint")

    print("Running test_security_auth_enforcement...")
    test_security_auth_enforcement()
    print("PASS: test_security_auth_enforcement")

    print("Running test_membership_inference_attack...")
    test_membership_inference_attack()
    print("PASS: test_membership_inference_attack")

    print("Running test_data_poisoning_attack...")
    test_data_poisoning_attack()
    print("PASS: test_data_poisoning_attack")

    print("Running test_retrieved_content_leakage_attack...")
    test_retrieved_content_leakage_attack()
    print("PASS: test_retrieved_content_leakage_attack")

    print("Running test_custom_dataset_upload_and_simulation...")
    test_custom_dataset_upload_and_simulation()

    print("Running test_production_threat_kb_integrity...")
    test_production_threat_kb_integrity()
    print("PASS: test_production_threat_kb_integrity")

    print("\n================ ALL 8 SECURITY TEST SUITES PASSED ================")


