# data/sources.py
import json
from pathlib import Path
from data.storage import load_dataset

import pandas as pd

from data.mock_data import generate_mock_data


def load_data(source="mock", path=None, dataset_id=None):
    """입력 방식에 따라 분석용 데이터를 반환한다."""

    if source == "mock":
        return generate_mock_data()

    if source == "mock_extended":
        from data.extended_mock import load_extended
        return load_extended()
    if source == "mock300":
        from data.mock300 import load_mock300
        return load_mock300()

    if source == "json":
        if path is None:
            raise ValueError("JSON 파일 경로가 필요합니다.")

        with Path(path).open("r", encoding="utf-8") as file:
            payload = json.load(file)

        if not isinstance(payload, dict):
            raise ValueError("JSON의 최상위 구조는 객체여야 합니다.")

        required_keys = ["policies", "metadata", "behavior"]
    

        for key in required_keys:
            if key not in payload:
                raise ValueError(f"필수 항목 누락: {key}")

            if not isinstance(payload[key], list):
                raise ValueError(f"{key}는 목록이어야 합니다.")

            if not payload[key]:
                raise ValueError(f"{key}가 비어 있습니다.")

            
            if not all(isinstance(row, dict) for row in payload[key]):
                raise ValueError(f"{key}의 각 항목은 객체여야 합니다.")

        return {
            "policies": payload["policies"],
            "metadata": pd.DataFrame(payload["metadata"]),
            "behavior": pd.DataFrame(payload["behavior"]),
        }
        
    if source == "sqlite":
        if dataset_id is None:
            raise ValueError("DB에서 읽을 데이터 ID가 필요합니다.")

        return load_dataset(dataset_id)

    raise ValueError(f"지원하지 않는 입력 방식: {source}")
