import pandas as pd

df = pd.read_csv("system_call_analysis.csv")

df["norm_count"] = df.groupby(["PID", "TID"])["count"].transform(lambda x: x / x.sum())
df["norm_total_time"] = df.groupby(["PID", "TID"])["total_time_ns"].transform(lambda x: x / x.sum())
df["score"] = 0.5 * df["norm_count"] + 0.5 * df["norm_total_time"]

labels = df.loc[df.groupby(["PID", "TID"])["score"].idxmax()][["PID", "TID", "Category"]]

labels.to_csv('PIDTID_labeled.csv')
print(labels)