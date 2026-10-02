# AICTE × Eastern Command — Security Challenges

Selection challenges for the **AICTE National Internship – Eastern Command (Kolkata)** programme: three hands-on tasks covering malware analysis, log forensics and signal intelligence.

**Author:** Aditya Narayan · B.Tech CSE

## Progress

| # | Challenge | Domain | Status | Folder |
|---|-----------|--------|--------|--------|
| 1 | Malware analysis | Static malware analysis / DFIR | ✅ Complete | [`challenge 1/`](challenge%201/) (samples not committed) |
| 2 | Log analysis — who was compromised and how | Endpoint threat hunting | ✅ Complete | [`challenge 2/`](challenge%202/) |
| 3 | Denoise & transcribe an intercepted audio file | Signal processing / SIGINT | ✅ Complete | [`challenge 3/`](challenge%203/) |

---

## Challenge 1 — Malware Analysis: USB-Spread DLL Side-Loading Loader

**Result:** identified the sample as a **USB-propagating worm that uses DLL side-loading**. Reconstructed the full infection chain on the victim PC from its Windows Prefetch records: 6 runs from 3 different USB drives and 4 persistent copies. The installed antivirus did not stop it.

| Metric | Value |
|--------|-------|
| Input | `victim_artifacts.7z`: 6 Windows Prefetch files + 3 samples (EXE, DLL, encrypted DAT) |
| Environment | REMnux VM in VirtualBox, network not attached, snapshot before the sample, hash-verified transfer |
| Analysis type | Static only: samples never executed, never uploaded |
| Key verdict | Malicious DLL 45/70 on VirusTotal (`trojan.zusy`, dropper, spreader); host EXE is a renamed legitimate LogMeIn binary |
| Stack | REMnux · capa · exiftool · strings · xxd · Python (Prefetch parser) · VirusTotal (hash search only) |

### Approach

1. **Isolate:** REMnux with no network; the sample moved in through a read-only mount and SHA-256 checked on both sides.
2. **Triage:** `file`, `xxd`, `exiftool`, `strings`. The EXE's metadata reveals it is LogMeIn's `LMIGuardianSvc.exe`, renamed.
3. **Capabilities:** capa on the DLL shows API hashing (PEB walk + FNV), anti-debug checks, a geolocation check, **RC4 decryption** and an **executable heap** (in-memory shellcode).
4. **Reputation:** VirusTotal hash lookups, sandbox behaviour and contacted infrastructure.
5. **Execution evidence:** my own [`parse_prefetch.py`](challenge%201/parse_prefetch.py) decompresses Windows 10/11 Prefetch (MAM / XPRESS-Huffman via `ntdll`) and recovers run counts, run times, source volumes and every file each program touched.

### Infection chain

```
Infected USB drive (fake "CD DRIVE.EXE", real files in invisible-Unicode-named folders)
   │  user double-clicks — 6 runs: 18 Mar, 28 May ×2, 8 Jul ×3
   ▼
%LOCALAPPDATA%\Temp\_READY_TEMP_\  ←  random EXE (renamed LogMeIn) + LMIGuardianDll.dll + encrypted .DAT
   │  0–5 s later
   ▼
Renamed EXE runs → Windows side-loads the malicious DLL (T1574.002)
   │
   ▼
DLL: anti-analysis → RC4-decrypts the .DAT → runs payload in memory
   ├─ Persistence: C:\ProgramData\<random>\ (4 copies)
   └─ Discovery + C2: gcdn[.]co / 92.223.96.6 (VirusTotal sandbox)
```

**Ruled out:** `AEXINSTALLPRECHECK.EXE` in the Prefetch set is a benign Symantec/Altiris agent installer.

Files: [`parse_prefetch.py`](challenge%201/parse_prefetch.py) · [`prefetch_report.txt`](challenge%201/prefetch_report.txt) · [`notes.txt`](challenge%201/notes.txt). Malware samples and raw Prefetch files are not committed.

---

## Challenge 2 — Endpoint Log Analysis: Who Is Compromised and How

**Result:** found **8 compromised endpoints** out of 248 across 7 units, 12 more that received malware the antivirus caught, and several antivirus false positives. Three of the most serious cases were missed or not stopped by the antivirus.

| Metric | Value |
|--------|-------|
| Input | 3 agent logs: web activity (2,812,118 rows), endpoint security (23,540), USB (8) |
| Coverage | 248 Linux desktops · 19 units · 1–26 Sep 2026 |
| Unique destinations analysed | 18,606 |
| Malicious quarantine records | 134 rows → 64 unique files on 33 endpoints (after de-duplication) |
| Stack | Python · pandas · PowerShell · VirusTotal (passive lookups only) |

### Approach

1. **Verify evidence:** SHA-256 of every log checked against the provided `SHA256SUMS`.
2. **Security log:** parse and de-duplicate quarantine records, separate real signature matches from file-type quarantines, find failed antivirus actions.
3. **Web log, six hunts:** public-IP lookup services, remote-access tools, fake-CDN domain patterns, beaconing (coefficient of variation of contact intervals), per-host timelines.
4. **Prevalence:** a destination contacted by only one of 248 endpoints is a strong compromise signal.
5. **Correlate and verify:** join all logs per endpoint, check indicators passively on VirusTotal, and rule out false positives with a specific explanation.

### Key findings

| Endpoint | How it was compromised | Antivirus caught it? |
|----------|------------------------|----------------------|
| host-de52 | Unauthorised anonymising proxy tunnel: config from GitHub, 3 IP lookups in 12 s, 23 foreign nodes no other host contacted | ❌ No alert |
| host-9a4f | Malicious `Final_Documents.zip` → AnyDesk remote-access sessions on 5 days | Zip only |
| host-423b | Phishing email; quarantine failed on 14 consecutive nights | ❌ Failed |
| host-508b, host-93eb | `.desktop` launcher files disguised as documents (APT36-style lure) | Type rule only, no signature |
| host-e53b, host-a976, host-a61e | Trojanised application launchers (persistence) | ✅ |

**False positives identified:** GNOME `recently-used.xbel` (identical hash on 9 machines), Microsoft Edge Wallet scripts, vendor printer drivers, and a "beacon" that was a Webex call left open.

Scripts: [`analyse_security.py`](challenge%202/analyse_security.py) · [`analyse_web.py`](challenge%202/analyse_web.py). Raw logs are not committed.

---

## Challenge 3 — Intercepted Audio: Denoising & Transcription

**Result:** recovered an intelligible 4 min 39 s voice recording hidden under four layers of deliberate noise, and produced a full timestamped transcript.

| Metric | Value |
|--------|-------|
| Input | `war-intercept.wav` — 16 kHz, mono, 16-bit PCM, 279 s |
| Noise components identified | 4 (tones, sweep, bursts, hiss) |
| Fixed tones removed | 10 frequencies (60 Hz hum + harmonics, 695–4200 Hz) |
| Output | `intercept_clean.wav` + transcript in 5 formats |
| Transcribed segments | 95 timestamped lines, language auto-detected as English |
| Stack | Python · NumPy · SciPy · Matplotlib · OpenAI Whisper · FFmpeg |

### 1. Identifying the noise

Each noise type has a distinct signature on a spectrogram, so I measured each one before removing it.

![Annotated spectrogram showing the four noise components](challenge%203/noise_identification.png)

| Noise | Spectrogram signature | Measured parameters | Removal technique |
|-------|----------------------|---------------------|-------------------|
| Constant tones | Horizontal lines | 60/120/180 Hz hum; 695, 700, 705, 1400, 2600, 2800, 4200 Hz | Zero-phase IIR notch filters |
| Triangle sweep | Zig-zag line | 200 → 4500 → 200 Hz, period 1.5 s | Modelled the sweep frequency per STFT frame and masked a ±110 Hz band around it |
| Broadband bursts | Evenly spaced vertical stripes | ~25 ms, every ~0.125 s | Detected via energy above 5 kHz; replaced with a temporal median |
| Background hiss | Uniform haze | Steady broadband | Spectral subtraction (20th-percentile noise floor) + 200–4000 Hz speech band-pass |

**Why model each noise instead of using a generic noise-reduction filter:** targeted removal strips only the noise and keeps as much of the voice as possible. A notch is a few Hz wide, and the sweep mask follows the tone as it moves.

### 2. Cleaning pipeline

```
war-intercept.wav
   │
   ├─ Notch filters ──────────── remove 10 fixed tones
   ├─ STFT (512-sample frames, 8 ms hop)
   ├─ Sweep mask ─────────────── time-varying, follows the 1.5 s triangle
   ├─ Burst suppression ──────── temporal median on burst frames
   ├─ Spectral subtraction ───── residual hiss
   ├─ Band-pass 200–4000 Hz ──── speech band only
   └─ Inverse STFT (original phase) → intercept_clean.wav
```

Script: [`challenge 3/denoise_intercept.py`](challenge%203/denoise_intercept.py)

### 3. Before vs after

![Spectrogram before and after denoising](challenge%203/before_after.png)

Tone lines and burst stripes are gone and the speech harmonics stand out. The faint dark zig-zag is where the sweep band was cut out.

### 4. Transcription

```powershell
cd "challenge 3"
python -m whisper intercept_clean.wav --model small
```

Whisper produced timestamped output in `.txt`, `.srt`, `.vtt`, `.tsv` and `.json`. Lines where the machine transcription is doubtful are flagged for manual review rather than guessed.

**Content:** a recorded letter home from an American officer in England, dated 30 December 1942, describing Christmas dinner with Queen Mary.

**Intelligence takeaway:** the speaker says *"I'm not supposed to tell you where I've been"*, yet reveals his location, the date, officers' names and ranks, and a high-profile event. It's a textbook OPSEC leak from personal communications.

### Run it yourself

```powershell
python -m pip install numpy scipy matplotlib openai-whisper   # FFmpeg must also be on PATH
cd "challenge 3"
python denoise_intercept.py          # → intercept_clean.wav, before_after.png
python -m whisper intercept_clean.wav --model small
```

> Audio files (`*.wav`), challenge archives (`*.7z`), raw logs and raw Prefetch files are excluded from version control via `.gitignore`.

---

## Repository layout

```
├── README.md
├── Readme.txt                  # original challenge brief
├── challenge 1/
│   ├── parse_prefetch.py       # Windows 10/11 Prefetch decoder (own script)
│   ├── prefetch_report.txt     # decoded execution records
│   └── notes.txt               # findings, hashes, IOCs
├── challenge 2/
│   ├── analyse_security.py     # antivirus / quarantine / web-filter analysis
│   ├── analyse_web.py          # six threat hunts over 2.8M web-log rows
│   └── output/                 # findings tables, reports, VirusTotal notes
└── challenge 3/
    ├── denoise_intercept.py    # denoising pipeline
    ├── noise_identification.png
    ├── before_after.png
    └── intercept_clean.{txt,srt,vtt,tsv,json}   # transcripts
```
