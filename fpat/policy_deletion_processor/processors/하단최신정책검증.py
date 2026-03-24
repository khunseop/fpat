import pandas as pd

def find_seq_mismatches(df: pd.DataFrame) -> pd.DataFrame:
    """
    REQUEST_ID별로 lowest_seq, latest_seq(리스트)를 찾아서
    lowest_seq가 latest_seq 중 하나가 아닌 경우만 반환.

    Parameters
    ----------
    df : pd.DataFrame
        컬럼: Seq, REQUEST_ID, REQUEST_START_DATE 포함
    
    Returns
    -------
    pd.DataFrame
        컬럼: REQUEST_ID, lowest_seq, latest_seq(list)
    """

    df df.copy()
    df["REQUEST_START_DATE"] = pd.to_datetime(df["REQUEST_START_DATE"], errors="coerce")

    results = []

    for rid, group in df.groupby("REQUEST_ID"):
        # 최신 날짜
        max_date = group["REQUEST_START_DATE"].max()
        # 최신 날짜에 해당하는 모든 seq
        latest_seqs = group.loc[group["REQUEST_START_DATE"] == max_date, "Seq"].tolist()
        # 최소 seq
        lowest_seq = group["Seq"].min()

        # lowest_seq가 latest_seqs 안에 없으면 결과에 추가
        if lowest_seq not in latest_seqs:
            results.append({
                "REQUEST_ID": rid,
                "lowest_seq": lowest_seq,
                "latest_seq": latest_seqs
            })
    
    return pd.DataFrame(results)

if __name__ == "__main__":
    df = pd.read_excel("seq검증.xlsx")

    result_df = find_seq_mismatches(df)

    # latest_seq 리스트를 풀어서 여러 행으로 변환
    exploded = result_df.explode("latest_seq").reset_index(drop=True)

    exploded.to_excel("seq검증결과.xlsx", index=False)

    print(exploded)