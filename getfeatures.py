import pandas as pd
import re


def convert_to_nanoseconds(timestamp_str):
    match = re.match(r'(\d{2}):(\d{2}):(\d{2})\.(\d{3})\s(\d{3})\s(\d{3})', timestamp_str)
    if not match:
        raise ValueError(f"Invalid timestamp format: {timestamp_str}")
    
    hours, minutes, seconds, millis, micros, nanos = map(int, match.groups())
    
    total_ns = (
        hours * 3_600_000_000_000 +  
        minutes * 60_000_000_000 +   
        seconds * 1_000_000_000 +    
        millis * 1_000_000 +         
        micros * 1_000 +             
        nanos                        
    )
    
    return total_ns

def extract_pid_tid(stream_ctx):
    pid = tid = None
    if pd.notna(stream_ctx):
        clean_ctx = stream_ctx.strip('[]"')
        pid_match = re.search(r'pid=(\d+)', clean_ctx)
        tid_match = re.search(r'tid=(\d+)', clean_ctx)
        
        pid = int(pid_match.group(1)) if pid_match else None
        tid = int(tid_match.group(1)) if tid_match else None
    return pid, tid


def extract_metrics(row):
    """Extract metrics from Packet and Stream Context strings"""
    metrics = {
        'TID': row['TID'],
        'PID': row['PID'],
        'Event type': row['Event type'],
        'Source': row['Source']
    }
    metrics['timestamp']=convert_to_nanoseconds(row['Timestamp'])
    
    packet_ctx = row['Packet Context']
    if pd.notna(packet_ctx):
        matches = re.findall(r'(\w+)=([^,\]]+)', packet_ctx)
        for key, value in matches:
            if key in ['timestamp_begin', 'timestamp_end', 'content_size', 
                      'packet_size', 'packet_seq_num', 'events_discarded']:
                metrics[key] = value.strip('"')
    
    stream_ctx = row['Stream Context']
    if pd.notna(stream_ctx):
        proc_match = re.search(r'procname="([^"]+)"', stream_ctx)
        if proc_match:
            metrics['procname'] = proc_match.group(1)
        pid_match = re.search(r'pid=([0-9]+)', stream_ctx)
        tid_match = re.search(r'tid=([0-9]+)', stream_ctx)
        
        if pid_match:
            metrics['PID'] = int(pid_match.group(1))  
        if tid_match:
            metrics['TID'] = int(tid_match.group(1))  
    
    if 'timestamp_begin' in metrics and 'timestamp_end' in metrics:
        try:
            metrics['timestamp_diff'] = int(metrics['timestamp_end']) - int(metrics['timestamp_begin'])
        except (ValueError, TypeError):
            metrics['timestamp_diff'] = None
    
    return metrics

df = pd.read_csv('holedata.csv', delimiter='\t', encoding="utf-8") 
filtered_df = df[df['Event type'].str.startswith('syscall', na=False)]
features = filtered_df[['Timestamp','TID', 'PID', 'Event type', 'Packet Context', 'Stream Context', 'Source']]
extracted_data = features.apply(extract_metrics, axis=1, result_type='expand')

final_columns = [
    'timestamp', 'content_size', 'packet_size', 'packet_seq_num',
    'events_discarded', 'procname', 'PID', 'TID', 'Source', 'Event type'
]
result_df = extracted_data.reindex(columns=[col for col in final_columns if col in extracted_data])

numeric_cols = ['timestamp', 'content_size', 'packet_size', 'packet_seq_num', 'events_discarded']
for col in numeric_cols:
    if col in result_df:
        result_df[col] = pd.to_numeric(result_df[col], errors='coerce')


categories_df = pd.read_csv('event_type_with_category.csv')
merged_df = pd.merge(
    result_df,
    categories_df,
    on='Event type',
    how='left'  
)

merged_df['Category'] = merged_df['Category'].fillna('Uncategorized')
merged_df[['call_type', 'syscall_name']] = merged_df['Event type'].str.extract(r'syscall_(entry|exit)_(\w+)')
merged_df = merged_df.sort_values(['PID', 'TID', 'syscall_name', 'timestamp'])
matched_pairs = []

for (pid, tid, syscall), group in merged_df.groupby(['PID', 'TID', 'syscall_name']):
    pending_entries = []
    
    for _, row in group.iterrows():
        if row['call_type'] == 'entry':
            pending_entries.append(row)
        elif row['call_type'] == 'exit' and pending_entries:
            entry = pending_entries.pop(0)
            duration = row['timestamp'] - entry['timestamp']
            
            if duration > 0: 
                matched_pairs.append({
                    'PID': pid,
                    'TID': tid,
                    'syscall_name': syscall,
                    'Category': entry['Category'],
                    'procname': entry['procname'],
                    'entry_ts': entry['timestamp'],
                    'exit_ts': row['timestamp'],
                    'duration_ns': duration
                })

pairs_df = pd.DataFrame(matched_pairs)
final_result = pairs_df.groupby(['PID', 'TID', 'Category', 'procname']).agg(
    count=('duration_ns', 'count'),
    total_time_ns=('duration_ns', 'sum'),
    avg_time_ns=('duration_ns', 'mean'),
    max_time_ns=('duration_ns', 'max')
).reset_index()

final_result.to_csv('system_call_analysis.csv', index=False)
print(f"Matched {len(pairs_df)} valid entry-exit pairs. Results saved to system_call_analysis.csv")





#features.to_csv('extracted_features.csv', index=False)
#print(features.head())
# event_counts = features['Event type'].value_counts().reset_index()
# event_counts.columns = ['Event type', 'Count']  # Rename columns for clarity
# print("Event Types and Their Counts:")
# print(event_counts)
