# Cell 2 정의 확인 및 Cell 6 정규화 연결 검증

import pandas as pd
from IPython.display import display

from data.mock_data import generate_mock_data
from preprocessing.normalizer import (
    GENERIC_ACTION_MAP,
    normalize_policy,
    to_graph,
    normalize_policy_dataset,
)

# --- 검증 코드 ---
print("Cell 2 core normalizer definitions loaded successfully.")
print("GENERIC_ACTION_MAP entries:", len(GENERIC_ACTION_MAP))
print("normalize_policy defined:", callable(normalize_policy))
print("to_graph defined:", callable(to_graph))

data = generate_mock_data()
mock_iam_policy_data = data["policies"]


# 1. 전체 IAM 데이터 정규화 실행
print("--- Cell 6: Unified IAM Normalization Integration Test ---")
print("1. Normalization execution completed")
normalized_records = normalize_policy_dataset(mock_iam_policy_data)
normalized_df = pd.DataFrame(normalized_records)

# 2. Unified IAM Normalization Summary 출력
print("\n2. Unified IAM Normalization Summary")
print("-------------------------------------")

total_raw_policy_entries = len(mock_iam_policy_data)
total_normalized_records = len(normalized_records)
unique_normalized_identities = normalized_df["identity"].nunique() if not normalized_df.empty else 0

print(f"Raw Policy Entries: {total_raw_policy_entries}")
print(f"Normalized IAM Records: {total_normalized_records}")
print(f"Unique Identities: {unique_normalized_identities}")

if not normalized_df.empty:
    print("\nRecords by CSP:")
    display(normalized_df["source_csp"].value_counts().rename_axis('CSP').rename('Count'))

    print("\nOperations:")
    display(normalized_df["operation"].value_counts().rename_axis('Operation').rename('Count'))

    wildcard_count = normalized_df["is_wildcard"].sum()
    print(f"\nWildcard Records: {wildcard_count}")
else:
    print("No records to display summary.")

# 3. Sample Unified IAM Records 출력 (컬럼 순서 지정)
print("\n3. Sample Unified IAM Records")
print("-------------------------------")
if not normalized_df.empty:
    display_cols = [
        "identity",
        "source_csp",
        "operation",
        "target",
        "effect",
        "is_wildcard"
    ]
    display(normalized_df[display_cols].head(10))
else:
    print("No normalized records to display.")

# 4. developer01 Normalized Records 출력
print("\n4. developer01 Normalized Records")
print("---------------------------------")
developer01_df = normalized_df[normalized_df["identity"] == "developer01"]
if not developer01_df.empty:
    display(developer01_df[display_cols])
else:
    print("developer01 records not found.")

# 5. UNKNOWN Taxonomy Records 출력
print("\n5. UNKNOWN Taxonomy Records")
print("-----------------------------")
unknown_df = normalized_df[normalized_df["operation"] == "UNKNOWN"]
unknown_count = len(unknown_df)
print(f"UNKNOWN operation count: {unknown_count}")
if not unknown_df.empty:
    display(unknown_df[display_cols].head(10))
else:
    print("No UNKNOWN operation records.")

# 6. Wildcard Records 출력
print("\n6. Wildcard Records")
print("---------------------")
wildcard_df = normalized_df[normalized_df["is_wildcard"] == True]
print(f"Wildcard Record Count: {len(wildcard_df)}")
if not wildcard_df.empty:
    display(wildcard_df[display_cols].head(10))
else:
    print("No wildcard records.")

# --- Integration Assertions Passed ---
print("\n7. Integration Assertions Passed")
print("--------------------------------")

# 5. Contract Validation
required_keys = {"identity", "operation", "target", "effect", "is_wildcard", "source_csp"}
for idx, record in enumerate(normalized_records):
    assert set(record.keys()) == required_keys, f"Record {idx} missing required keys or has extra keys.\nRecord: {record}"
    assert isinstance(record["identity"], str), f"Record {idx} identity type mismatch. Value: {record['identity']}"
    assert isinstance(record["operation"], str), f"Record {idx} operation type mismatch. Value: {record['operation']}"
    assert isinstance(record["target"], str), f"Record {idx} target type mismatch. Value: {record['target']}"
    assert isinstance(record["effect"], str), f"Record {idx} effect type mismatch. Value: {record['effect']}"
    assert isinstance(record["is_wildcard"], bool), f"Record {idx} is_wildcard type mismatch. Value: {record['is_wildcard']}"
    assert isinstance(record["source_csp"], str), f"Record {idx} source_csp type mismatch. Value: {record['source_csp']}"
print("Contract validation (keys and types) successful.")

# 6. Empty Result 방지
assert len(normalized_records) > 0, "Normalized records list is empty."
assert not normalized_df.empty, "Normalized DataFrame is empty."
print("Empty result check successful.")

# 7. 모든 CSP가 실제로 정규화되었는지 확인
expected_csps = set(item["csp"] for item in mock_iam_policy_data)
actual_csps = set(normalized_df["source_csp"])
assert expected_csps == actual_csps, f"CSP coverage mismatch. Expected: {expected_csps}, Actual: {actual_csps}"
for csp in expected_csps:
    assert (normalized_df["source_csp"] == csp).any(), f"No records found for CSP: {csp}"
print("All expected CSPs are present in normalized records.")

# 8. Identity Consistency Validation
known_identities = set(item["identity"] for item in mock_iam_policy_data)
normalized_identities = set(normalized_df["identity"])
assert normalized_identities.issubset(known_identities), "Normalized identities contain unknown identities."
assert not normalized_df["identity"].str.contains("arn:", regex=False).any(), "Normalized identities contain 'arn:'."
assert not normalized_df["identity"].str.contains("user:", regex=False).any(), "Normalized identities contain 'user:'."

# GCP user principals should not contain '@' (service accounts are allowed)
for identity_val in normalized_df["identity"].unique():
    if not identity_val.startswith('serviceAccount:') and '@' in identity_val:
        raise AssertionError(f"GCP user principal '{identity_val}' contains '@' after canonicalization.")
print("Identity canonicalization and consistency validated.")

# 9. developer01 핵심 검증 (s3:*, iam:PassRole -> UNKNOWN, is_wildcard)
assert not developer01_df.empty, "developer01_df is empty."

# 10. developer01 Wildcard Detection
assert developer01_df["is_wildcard"].any(), "developer01 records should contain at least one wildcard."
print("developer01 wildcard detection successful.")

# 11. Known Operation Validation (READ, CREATE)
developer_ops = set(developer01_df["operation"])
assert "READ" in developer_ops, "developer01 records should contain 'READ' operation."
assert "CREATE" in developer_ops, "developer01 records should contain 'CREATE' operation."
print("developer01 READ/CREATE operation validation successful.")

# 12. UNKNOWN Operation Validation (developer01)
assert (developer01_df["operation"] == "UNKNOWN").any(), "developer01 records should contain at least one 'UNKNOWN' operation."
print("developer01 UNKNOWN operation validation successful.")

print("\nCell 6 Unified IAM Normalization Integration Test completed successfully.")