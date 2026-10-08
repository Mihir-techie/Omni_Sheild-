import io
import struct
import wave

import numpy as np
import pytest
from PIL import Image

from app.modules.deepfake import engine as d


def pink(n=512, seed=0):
    rng = np.random.default_rng(seed)
    f = np.fft.fftfreq(n)
    fx, fy = np.meshgrid(f, f)
    r = np.hypot(fx, fy)
    r[0, 0] = 1
    spec = (rng.normal(size=(n, n)) + 1j * rng.normal(size=(n, n))) / r
    spec[0, 0] = 0
    img = np.fft.ifft2(spec).real
    return (img - img.min()) / (img.max() - img.min()) * 255


def encode(arr, fmt="PNG", **kw):
    buf = io.BytesIO()
    Image.fromarray(arr.clip(0, 255).astype(np.uint8)).save(buf, fmt, **kw)
    return buf.getvalue()


def make_wav(x, sr):
    pcm = (np.clip(x, -1, 1) * 32767).astype("<i2")
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(sr)
        w.writeframes(pcm.tobytes())
    return buf.getvalue()


def lowpass_noise(sr, seconds, cutoff_hz, seed=0):
    rng = np.random.default_rng(seed)
    x = rng.normal(size=int(sr * seconds))
    spec = np.fft.rfft(x)
    freqs = np.fft.rfftfreq(len(x), 1 / sr)
    spec[freqs > cutoff_hz] = 0
    y = np.fft.irfft(spec, len(x))
    return 0.2 * y / np.abs(y).max()


def codes(r):
    return {f.code for f in r.findings}


def test_format_sniffing_ignores_extension_and_rejects_unknown():
    with pytest.raises(d.UnsupportedMediaError):
        d.analyze(b"MZ\x90\x00 not media at all")


def test_clean_images_do_not_trigger_spectral_peaks():
    for seed in range(3):
        for fmt, kw in (("PNG", {}), ("JPEG", {"quality": 85})):
            assert "spectral_peaks" not in codes(d.analyze(encode(pink(seed=seed), fmt, **kw)))


def test_periodic_grid_artifacts_are_flagged():
    yy, xx = np.indices((512, 512))
    grid = 6 * (np.sin(2 * np.pi * xx / 4) + np.sin(2 * np.pi * yy / 4)
                + np.sin(2 * np.pi * (xx + yy) / 6) + np.sin(2 * np.pi * xx / 3))
    r = d.analyze(encode(pink(seed=1) + grid))
    assert "spectral_peaks" in codes(r)


def test_image_score_alone_cannot_reach_critical():
    assert d.analyze(encode(pink())).score < 80


def test_corrupt_and_tiny_images_rejected():
    with pytest.raises(d.MediaError):
        d.analyze(b"\x89PNG\r\n\x1a\n" + b"garbage")
    with pytest.raises(d.MediaError):
        d.analyze(encode(np.zeros((32, 32))))


def test_wav_sharp_8khz_cutoff_flagged_as_vocoder_like():
    r = d.analyze(make_wav(lowpass_noise(24_000, 3, 8_000), 24_000))
    assert "wav_vocoder_cutoff" in codes(r)


def test_wideband_wav_not_flagged():
    r = d.analyze(make_wav(lowpass_noise(24_000, 3, 11_900), 24_000))
    assert not codes(r) & {"wav_vocoder_cutoff", "wav_bandlimited"}


def test_other_cutoff_is_only_bandlimited():
    r = d.analyze(make_wav(lowpass_noise(44_100, 3, 15_000), 44_100))
    assert "wav_vocoder_cutoff" not in codes(r)


def test_low_sample_rate_wav_is_not_assessable():
    r = d.analyze(make_wav(lowpass_noise(16_000, 3, 7_000), 16_000))
    assert r.score == 0 and any("8 kHz" in n for n in r.notes)


def test_corrupt_wav_rejected():
    with pytest.raises(d.MediaError):
        d.analyze(b"RIFF" + struct.pack("<I", 4) + b"WAVE" + b"junk")
