# AICTE × Eastern Command — Security Challenges

Selection challenges for the **AICTE National Internship – Eastern Command (Kolkata)** programme: three hands-on tasks covering malware analysis, log forensics and signal intelligence.

**Author:** Aditya Narayan · B.Tech CSE

## Progress

| # | Challenge | Domain | Status | Folder |
|---|-----------|--------|--------|--------|
| 1 | Malware analysis | Reverse engineering / IOCs | ⏳ Planned | `challenge 1/` (sample not committed) |
| 2 | Log analysis — who was compromised and how | Web forensics | ⏳ Planned | `challenge 2/` |
| 3 | Denoise & transcribe an intercepted audio file | Signal processing / SIGINT | ✅ Complete | [`challenge 3/`](challenge%203/) |

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

> Audio files (`*.wav`) and challenge archives (`*.7z`) are excluded from version control via `.gitignore`.

---

## Repository layout

```
├── README.md
├── Readme.txt                  # original challenge brief
└── challenge 3/
    ├── denoise_intercept.py    # denoising pipeline
    ├── noise_identification.png
    ├── before_after.png
    └── intercept_clean.{txt,srt,vtt,tsv,json}   # transcripts
```
