# checks/check_json_input.py
import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

import pandas as pd

from data.mock_data import generate_mock_data
from pipeline import run_pipeline


def main():
    # 프로젝트 위치를 기준으로 파일 경로 설정
    project_root = Path(__file__).resolve().parents[1]
    json_path = project_root / "data" / "sample_input.json"

    # 기존 목 데이터를 JSON에 저장 가능한 형태로 변환
    data = generate_mock_data()

    # DataFrame의 결측값을 Python의 None으로 변환
    metadata = data["metadata"].astype(object)
    metadata = metadata.where(pd.notna(metadata), None)

    behavior = data["behavior"].astype(object)
    behavior = behavior.where(pd.notna(behavior), None)

    payload = {
        "policies": data["policies"],
        "metadata": metadata.to_dict(orient="records"),
        "behavior": behavior.to_dict(orient="records"),
    }

    with json_path.open("w", encoding="utf-8") as file:
        json.dump(
            payload,
            file,
            ensure_ascii=False,
            indent=2,
            allow_nan=False,
        )

    print(f"JSON 저장 완료: {json_path}")

    # 긴 분석 출력은 숨기고 두 입력 경로를 실행
    with redirect_stdout(StringIO()):
        mock_state = run_pipeline(data=data)

        json_state = run_pipeline(
            source="json",
            path=json_path,
        )

    # 목 입력과 JSON 입력의 모든 DataFrame 결과 비교
    mock_frames = {
        key: value
        for key, value in mock_state.items()
        if isinstance(value, pd.DataFrame)
    }

    json_frames = {
        key: value
        for key, value in json_state.items()
        if isinstance(value, pd.DataFrame)
    }

    if mock_frames.keys() != json_frames.keys():
        raise AssertionError("두 실행의 결과 항목이 다릅니다.")

    for key in mock_frames:
        pd.testing.assert_frame_equal(
            mock_frames[key],
            json_frames[key],
            check_exact=True,
            obj=key,
        )

    print(
        f"검증 성공: DataFrame {len(mock_frames)}개 결과가 "
        "모두 정확히 일치합니다."
    )


if __name__ == "__main__":
    main()