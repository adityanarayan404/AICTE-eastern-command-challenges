# Challenge 2 - Step 4: hunt through 2.8 million web-log rows for signs of compromise
# Run from inside "challenge 2":  python analyse_web.py > output\web_report.txt
# NOTE: destinations printed here may be malicious - never open them in a browser.
import pandas as pd, numpy as np, os

pd.set_option('display.width', 250); pd.set_option('display.max_rows', 300); pd.set_option('display.max_colwidth', 60)
os.makedirs('output', exist_ok=True)

w = pd.read_csv('web_activity/data/web_activity.csv', usecols=['endpoint_name', 'unit', 'event_time', 'message'])
w['t'] = pd.to_datetime(w.event_time, format='%d-%m-%Y %H:%M:%S')
# routers append their own search domain (example.com.hgu_lan) - strip it so the same site counts once
w['dest'] = w.message.str.lower().str.replace(r'\.(hgu_lan|bbrouter|dlink|local|lan|home|domain|localdomain|router)\.?$', '', regex=True)
prevalence = w.groupby('dest').endpoint_name.nunique()      # how many endpoints contacted each destination
w['prev'] = w.dest.map(prevalence)
print(f'{len(w):,} rows | {w.endpoint_name.nunique()} endpoints | {w.dest.nunique():,} destinations | {w.t.min()} -> {w.t.max()}\n')

def summary(x):
    return (x.groupby(['endpoint_name', 'unit', 'dest'])
             .agg(hits=('t', 'size'), first=('t', 'min'), last=('t', 'max'), days=('t', lambda s: s.dt.date.nunique()))
             .reset_index().sort_values(['endpoint_name', 'first']))

# HUNT 1 - "what is my public IP?" services: normal software rarely needs them, malware does it first thing
iplookup = w[w.dest.str.contains(r'ipify|ipinfo\.io|ip-api\.com|seeip|ipwho\.is|icanhazip|ifconfig\.me|checkip|myip', regex=True)]
print('=== HUNT 1: public-IP lookup services ===')
print(summary(iplookup).to_string(index=False), '\n')

# HUNT 2 - remote-access tools: legit for IT, but also how attackers get hands-on-keyboard access
remote = w[w.dest.str.contains(r'anydesk|teamviewer|rustdesk|ngrok|remotedesktop|screenconnect|realvnc', regex=True)]
print('=== HUNT 2: remote-access tools ===')
print(summary(remote).to_string(index=False), '\n')

# HUNT 3 - fake-CDN infrastructure: <country><number>.<cdn-sounding-word>.xyz/.live, e.g. gr44.cdnaccelerate.xyz
fakecdn = w[w.dest.str.match(r'^[a-z]{2,3}\d{1,3}\.[a-z]+\.(xyz|live)$') | w.dest.str.endswith('bmtr.org')]
print('=== HUNT 3: fake-CDN / numbered C2-style domains ===')
print(summary(fakecdn).to_string(index=False), '\n')

# HUNT 4 - beaconing: a rare destination (<=3 endpoints) contacted many times at a steady rhythm.
# CV = std/mean of the gap between contacts. Humans browse in bursts (CV > 2); timers give CV < 1.
rare = w[w.prev <= 3]
rows = []
for (ep, unit, dest), s in rare.groupby(['endpoint_name', 'unit', 'dest']).t:
    s = s.drop_duplicates().sort_values()
    if len(s) < 50: continue
    gaps = s.diff().dt.total_seconds().dropna()
    rows.append((ep, unit, dest, len(s), gaps.median(), gaps.std() / gaps.mean(), s.min(), s.max()))
beacons = pd.DataFrame(rows, columns=['endpoint_name', 'unit', 'dest', 'hits', 'median_gap_s', 'cv', 'first', 'last'])
print('=== HUNT 4: regular-interval contacts to rare destinations (lowest CV = most machine-like) ===')
print(beacons.sort_values('cv').head(15).to_string(index=False), '\n')

# HUNT 5 - first minutes of host-de52 in the logs: IP check, then C2 within seconds
de52 = w[(w.endpoint_name == 'host-de52') & (w.prev <= 3)].sort_values('t')
print('=== HUNT 5: host-de52 - first rare destinations it contacted ===')
print(de52.drop_duplicates('dest')[['t', 'dest', 'prev']].head(25).to_string(index=False), '\n')

# HUNT 6 - host-9a4f: AnyDesk sessions per day after the malicious zip (quarantined 10 Sep)
ad = w[(w.endpoint_name == 'host-9a4f') & w.dest.str.contains('anydesk')]
print('=== HUNT 6: host-9a4f AnyDesk relay contacts per day ===')
print(ad.groupby(ad.t.dt.date).agg(contacts=('t', 'size'), first=('t', 'min'), last=('t', 'max')).to_string())

pd.concat([summary(iplookup), summary(remote), summary(fakecdn)]).to_csv('output/web_hunts.csv', index=False)
beacons.sort_values('cv').to_csv('output/beacons.csv', index=False)
