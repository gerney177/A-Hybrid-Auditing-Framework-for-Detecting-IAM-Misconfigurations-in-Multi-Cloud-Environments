from contextlib import redirect_stdout
from io import StringIO

import pandas as pd

from pipeline import run_pipeline
from data.sources import load_data
from data.storage import (
    DB_PATH,
    save_dataset,
    load_dataset,
    save_analysis_run,
    list_analysis_runs,
    load_analysis_run,
)



def main():
    original = load_data(source="mock")

    dataset_id = save_dataset(
        data=original,
        source="mock",
    )

    restored = load_dataset(dataset_id)

    # 정책 내용 비교
    assert original["policies"] == restored["policies"]

    # 결측값 표현을 통일한 뒤 DataFrame 비교
    for key in ["metadata", "behavior"]:
        before = original[key].fillna(value="")
        after = restored[key].fillna(value="")

        pd.testing.assert_frame_equal(
            before,
            after,
            check_exact=True,
            obj=key,
        )
    # 원본 입력과 DB 입력으로 각각 전체 분석 실행
    with redirect_stdout(StringIO()):
        original_state = run_pipeline(data=original)

        stored_state = run_pipeline(
            source="sqlite",
            dataset_id=dataset_id,
        )

    # 두 실행에서 반환한 모든 DataFrame 비교
    original_frames = {
        key: value
        for key, value in original_state.items()
        if isinstance(value, pd.DataFrame)
    }

    stored_frames = {
        key: value
        for key, value in stored_state.items()
        if isinstance(value, pd.DataFrame)
    }

    assert original_frames.keys() == stored_frames.keys()

    for key in original_frames:
        pd.testing.assert_frame_equal(
            original_frames[key],
            stored_frames[key],
            check_exact=True,
            obj=key,
        )

    print(
        f"분석 검증 성공: DataFrame {len(original_frames)}개가 "
        "모두 정확히 일치합니다."
    )
        # 검증을 마친 분석 결과 저장
    run_id = save_analysis_run(
        dataset_id=dataset_id,
        state=stored_state,
    )

        # 방금 저장한 분석 결과를 DB에서 다시 읽기
    saved = load_analysis_run(run_id)

    assert saved["dataset_id"] == dataset_id

    # JSON에 저장한 내용이 그대로 복원됐는지 비교
    result_keys = [
        "integrated_risk_df",
        "post_integrated_risk_df",
        "remediation_plan_df",
        "remediation_effect_df",
    ]

    for key in result_keys:
        expected_json = stored_state[key].to_json(
            orient="records",
            force_ascii=False,
            double_precision=15,
        )

        restored_json = saved["results"][key].to_json(
            orient="records",
            force_ascii=False,
            double_precision=15,
        )

        assert expected_json == restored_json, (
            f"저장한 분석 결과가 다릅니다: {key}"
        )

    print("결과 조회 검증 성공: 분석 결과 4개가 복원됐습니다.")
    history = list_analysis_runs()

    # 이번 실행이 실제 목록에 있는지 확인
    saved_run = history.loc[history["run_id"].eq(run_id)]

    assert len(saved_run) == 1
    assert int(saved_run.iloc[0]["dataset_id"]) == dataset_id

    print(f"분석 결과 저장 완료: 실행 ID {run_id}")
    print(history.head(5).to_string(index=False))
    print(f"DB 위치: {DB_PATH}")
    print(f"저장한 데이터 ID: {dataset_id}")
    print("검증 성공: 저장 전후 입력 데이터가 일치합니다.")


if __name__ == "__main__":
    main()
