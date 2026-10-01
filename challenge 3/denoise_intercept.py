# Challenge 3 - denoise war-intercept.wav
# Needs: pip install numpy scipy matplotlib
import numpy as np, scipy.io.wavfile as w, scipy.signal as ss, scipy.ndimage as nd
import matplotlib.pyplot as plt

sr, x = w.read('war-intercept.wav'); x = x.astype(float) / 32768

# STEP 1 - remove constant tones (60 Hz hum + 700/1400/2600/2800/4200 Hz) with notch filters
y = x.copy()
for f0 in [60, 120, 180, 695, 700, 705, 1400, 2600, 2800, 4200]:
    b, a = ss.iirnotch(f0, f0/4 if f0 > 200 else 10, sr)
    y = ss.filtfilt(b, a, y)

# go to time-frequency domain (STFT): 512-sample frames, 8 ms hop
f, t, Z = ss.stft(y, sr, nperseg=512, noverlap=384)
A, phase = np.abs(Z), np.angle(Z)

# STEP 2 - remove triangle sweep (200 -> 4500 -> 200 Hz, period 1.5 s, found from spectrogram)
tri = lambda u: 1 - np.abs(2*(u % 1) - 1)
sweep_f = 200 + 4300*tri(t/1.5)
M = np.ones_like(A)
M[np.abs(f[:, None] - sweep_f[None, :]) < 110] = 0.02

# STEP 3 - remove noise bursts (~25 ms broadband bursts every ~0.125 s)
smooth = nd.median_filter(A, size=(1, 31))          # median over time ignores short bursts
hi = A[f > 5000].mean(0)                            # bursts show up as energy above 5 kHz
burst = hi > np.median(hi)*2.5
G = np.where(burst[None, :], np.minimum(1, smooth/(A+1e-12)), 1.0)
A2 = A*M*G

# STEP 4 - spectral subtraction for the remaining hiss
noise = np.percentile(A2[:, ~burst], 20, axis=1)[:, None]
gain = np.maximum(1 - 1.5*(noise/(A2+1e-12))**2, 0.05)
A3 = A2*nd.uniform_filter(gain, size=(3, 3))

# STEP 5 - keep only the speech band (200-4000 Hz)
A3[(f < 200) | (f > 4000)] *= 0.05

_, out = ss.istft(A3*np.exp(1j*phase), sr, nperseg=512, noverlap=384)
out = out[:len(x)]; out = out/np.abs(out).max()*0.9
w.write('intercept_clean.wav', sr, (out*32767).astype(np.int16))

fig, ax = plt.subplots(2, 1, figsize=(16, 8))
for a_, s, title in [(ax[0], x, 'Original (0-15 s)'), (ax[1], out, 'Cleaned (0-15 s)')]:
    a_.specgram(s[:sr*15], Fs=sr, NFFT=512, noverlap=384, cmap='magma'); a_.set_title(title); a_.set_ylabel('Hz')
plt.xlabel('seconds'); plt.tight_layout(); plt.savefig('before_after.png', dpi=100)
print('done -> intercept_clean.wav, before_after.png')
