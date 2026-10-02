# Challenge 2 - Step 3: what did the antivirus / quarantine / web filter see?
# Run from inside "challenge 2":  python analyse_security.py
import pandas as pd, os

pd.set_option('display.width', 250); pd.set_option('display.max_colwidth', 70); pd.set_option('display.max_rows', 200)
os.makedirs('output', exist_ok=True)

d = pd.read_csv('web_activity/data/endpoint_security.csv')
d['event_time'] = pd.to_datetime(d.event_time, format='%d-%m-%Y %H:%M:%S')
print(f'{len(d):,} rows | {d.endpoint_id.nunique()} endpoints | {d.unit.nunique()} units')
print(d.log_type.value_counts().to_string(), '\n')

# 1) Quarantine records -> split "File: x | Quarantined At: y | FileType: z | SHA256: h" into columns
q = d[d.log_type == 'quarantine'].copy()
parts = q.message.str.extract(r'File: (?P<file>.*?) \| Quarantined At: (?P<qtime>.*?) \| FileType: (?P<ftype>.*?) \| SHA256: (?P<sha256>\w+)')
q = q.join(parts).dropna(subset=['file'])
print('Quarantine file types (Malicious = signature match, others = only by type/extension):')
print(q.ftype.value_counts().to_string(), '\n')

# the service re-lists the whole folder at every scan -> keep one row per endpoint + file + hash
mal = (q[q.ftype == 'Malicious']
       .groupby(['endpoint_name', 'unit', 'file', 'sha256'])
       .agg(quarantined_at=('qtime', 'min'), times_listed=('qtime', 'size'))
       .reset_index().sort_values('quarantined_at'))
print(f'=== MALICIOUS files: {len(mal)} unique, on {mal.endpoint_name.nunique()} endpoints ===')
print(mal.drop(columns='sha256').to_string(index=False), '\n')
mal.to_csv('output/malicious_quarantine.csv', index=False)

# 2) Same file hash on several machines = spread, or one common file (possible false positive)
spread = mal.groupby('sha256').agg(file=('file', 'first'), endpoints=('endpoint_name', 'nunique')).query('endpoints > 1')
print('=== Hashes found on more than one endpoint ===')
print(spread.to_string(), '\n')

# 3) Nightly AV scan: what it tried to do with each file - and where it FAILED
av = d[d.log_type == 'av_scan'].copy()
av['msg'] = av.message.str.replace('Infected file is ', '', regex=False)
act = av[av.msg.str.match(r"(Quarantined and deleted|File not found or no permissions)")].copy()
act['action'] = act.msg.str.split(':').str[0]
act['path'] = act.msg.str.split(': ', n=1).str[1].str.split(' to ').str[0].str.strip("'")
av_sum = (act.groupby(['endpoint_name', 'unit', 'action', 'path'])
          .agg(first=('event_time', 'min'), last=('event_time', 'max'), nights=('event_time', 'nunique'))
          .reset_index().sort_values('first'))
print('=== AV scan actions (a FAILED quarantine means the file stayed on disk) ===')
print(av_sum.to_string(index=False), '\n')
av_sum.to_csv('output/av_actions.csv', index=False)

# 4) Web filter blocks: which endpoints tried to reach blocked destinations most
wb = d[d.log_type == 'web_block']
print('=== Web-filter blocks: top endpoints ===')
print(wb.groupby(['endpoint_name', 'unit']).size().sort_values(ascending=False).head(15).to_string(), '\n')
print('=== Web-filter blocks: top destinations (DO NOT open these) ===')
print(wb.message.value_counts().head(25).to_string())
wb.to_csv('output/web_blocks.csv', index=False)
