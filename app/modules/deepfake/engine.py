"""Module 2 - frequency-domain triage for images (JPEG/PNG/WebP) and WAV audio.

These are weak, uncalibrated heuristics. They flag spectral/gradient patterns that are *sometimes*
associated with generated media; they cannot establish authenticity either way. All thresholds live
in `T` so they can be calibrated on a labelled dataset before any real use.
"""

from __future__ import annotations

import io
import wave

import numpy as np
from PIL import Image, UnidentifiedImageError

from app.shared.models import Finding, ModuleResult


class MediaError(ValueError):
    """Corrupt or unanalysable media (HTTP 422)."""


class UnsupportedMediaError(MediaError):
    """Not one of the supported formats (HTTP 415)."""


T = {
    "max_pixels": 25_000_000,
    "min_side": 64,
    "crop": 512,
    "peak_z": 6.0,
    "peak_ratio_mid": 2e-5,
    "peak_ratio_high": 1e-4,
    "peak_ratio_severe": 5e-4,
    "hf_ratio_low": 2e-3,
    "hf_ratio_high": 0.30,
    "block": 16,
    "grad_smooth": 1.5,
    "grad_sharp": 10.0,
    "abrupt_fraction": 0.08,
    "n_fft": 2048,
    "cutoff_drop_db": 25.0,
    "cutoff_band_hz": 500,
}


def sniff_format(data: bytes) -> str:
    """Identify format from magic bytes (never trust the client's content-type)."""
    if data[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data[:4] == b"RIFF" and data[8:12] == b"WAVE":
        return "wav"
    raise UnsupportedMediaError("Unsupported file type; use JPEG, PNG, WebP or WAV")


# ----------------------------------------------------------------------------- images


def _load_gray(data: bytes) -> np.ndarray:
    try:
        img = Image.open(io.BytesIO(data))
        w, h = img.size
        if w * h > T["max_pixels"]:
            raise MediaError("Image is too large to analyse")
        if min(w, h) < T["min_side"]:
            raise MediaError(f"Image is too small (minimum {T['min_side']}x{T['min_side']})")
        gray = np.asarray(img.convert("L"), dtype=np.float32)
    except MediaError:
        raise
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError) as exc:
        raise MediaError("Image is corrupt or could not be decoded") from exc
    n = min(T["crop"], gray.shape[0], gray.shape[1])
    n -= n % 2
    y0, x0 = (gray.shape[0] - n) // 2, (gray.shape[1] - n) // 2
    return gray[y0 : y0 + n, x0 : x0 + n]


def spectral_features(g: np.ndarray, jpeg: bool) -> dict[str, float]:
    n = g.shape[0]
    win = np.hanning(n).astype(np.float32)
    spec = np.fft.fftshift(np.fft.fft2((g - g.mean()) * np.outer(win, win)))
    amp = np.abs(spec)
    logmag = np.log1p(amp)
    c = n // 2
    yy, xx = np.indices((n, n))
    dy, dx = yy - c, xx - c
    r = np.hypot(dx, dy).astype(np.int32)

    prof = np.bincount(r.ravel(), weights=logmag.ravel()) / np.maximum(np.bincount(r.ravel()), 1)
    resid = logmag - prof[r]

    band = (r >= int(0.25 * c)) & (r <= int(0.95 * c)) & (np.abs(dx) > 1) & (np.abs(dy) > 1)
    if jpeg:  # mask harmonics of the 8x8 JPEG block grid so they are not mistaken for GAN grids
        step = max(n // 8, 2)
        near = lambda d: np.minimum(np.abs(d) % step, step - np.abs(d) % step) <= 1  # noqa: E731
        band &= ~(near(dx) | near(dy))
    vals = resid[band]
    med = np.median(vals)
    mad = np.median(np.abs(vals - med)) * 1.4826 + 1e-9
    peak_ratio = float(((vals - med) / mad > T["peak_z"]).mean())

    power = amp.astype(np.float64) ** 2
    total = power[r > 1].sum() + 1e-12
    hf_ratio = float(power[r > 0.5 * c].sum() / total)
    return {"peak_ratio": peak_ratio, "hf_ratio": hf_ratio}


def gradient_features(g: np.ndarray) -> dict[str, float]:
    gy, gx = np.gradient(g)
    mag = np.hypot(gx, gy)
    b = T["block"]
    nb = g.shape[0] // b
    blocks = mag[: nb * b, : nb * b].reshape(nb, b, nb, b).mean(axis=(1, 3))
    smooth, sharp = blocks < T["grad_smooth"], blocks > T["grad_sharp"]
    h = (smooth[:, :-1] & sharp[:, 1:]) | (sharp[:, :-1] & smooth[:, 1:])
    v = (smooth[:-1, :] & sharp[1:, :]) | (sharp[:-1, :] & smooth[1:, :])
    abrupt = float((h.sum() + v.sum()) / (h.size + v.size))
    return {"abrupt_fraction": abrupt, "smooth_fraction": float(smooth.mean())}


def analyze_image(data: bytes, fmt: str) -> ModuleResult:
    g = _load_gray(data)
    spec = spectral_features(g, jpeg=(fmt == "jpeg"))
    grad = gradient_features(g)
    findings: list[Finding] = []

    pr = spec["peak_ratio"]
    pts = 40 if pr >= T["peak_ratio_severe"] else 25 if pr >= T["peak_ratio_high"] else (
        12 if pr >= T["peak_ratio_mid"] else 0
    )
    if pts:
        findings.append(Finding("spectral_peaks", pts, {"peak_pct": f"{pr * 100:.3f}"}))
    if spec["hf_ratio"] < T["hf_ratio_low"] or spec["hf_ratio"] > T["hf_ratio_high"]:
        direction = "unusually low" if spec["hf_ratio"] < T["hf_ratio_low"] else "unusually high"
        findings.append(
            Finding("hf_energy_anomaly", 12, {"direction": direction, "hf_ratio": f"{spec['hf_ratio']:.4f}"})
        )
    if grad["abrupt_fraction"] > T["abrupt_fraction"]:
        findings.append(
            Finding("smooth_blend_boundaries", 10, {"pct": f"{grad['abrupt_fraction'] * 100:.1f}"})
        )

    notes = [
        "Thresholds are uncalibrated placeholders; treat as a triage signal only.",
        "Gradient check is not face-localised (no face detector is bundled) and can fire on "
        "portraits with soft backgrounds or screenshots.",
    ]
    if fmt in ("jpeg", "webp"):
        notes.append("Lossy compression alters frequency statistics and lowers confidence.")
    evidence = {
        "format": fmt,
        "analysed_size": list(g.shape),
        "peak_ratio": round(spec["peak_ratio"], 6),
        "hf_energy_ratio": round(spec["hf_ratio"], 5),
        "abrupt_block_fraction": round(grad["abrupt_fraction"], 4),
        "smooth_block_fraction": round(grad["smooth_fraction"], 4),
    }
    return ModuleResult("deepfake", findings, evidence, notes)


# ------------------------------------------------------------------------------ audio


def _read_wav(data: bytes) -> tuple[np.ndarray, int]:
    try:
        with wave.open(io.BytesIO(data)) as w:
            ch, width, sr, nframes = w.getnchannels(), w.getsampwidth(), w.getframerate(), w.getnframes()
            raw = w.readframes(nframes)
    except (wave.Error, EOFError) as exc:
        raise MediaError("WAV is corrupt or not uncompressed PCM") from exc
    if nframes == 0 or ch == 0 or sr <= 0:
        raise MediaError("WAV contains no audio")
    if width == 1:
        x = (np.frombuffer(raw, dtype=np.uint8).astype(np.float32) - 128.0) / 128.0
    elif width == 2:
        x = np.frombuffer(raw, dtype="<i2").astype(np.float32) / 32768.0
    elif width == 3:
        b = np.frombuffer(raw[: len(raw) // 3 * 3], dtype=np.uint8).reshape(-1, 3).astype(np.int32)
        v = b[:, 0] | (b[:, 1] << 8) | (b[:, 2] << 16)
        x = np.where(v & 0x800000, v - 0x1000000, v).astype(np.float32) / 8388608.0
    elif width == 4:
        x = np.frombuffer(raw, dtype="<i4").astype(np.float32) / 2147483648.0
    else:
        raise MediaError("Unsupported WAV sample width")
    x = x[: len(x) // ch * ch].reshape(-1, ch).mean(axis=1)
    return x, sr


def find_cutoff(x: np.ndarray, sr: int) -> tuple[float, float] | None:
    """Return (cutoff_hz, drop_db) of the steepest spectral step between 4 kHz and Nyquist."""
    n_fft = T["n_fft"]
    hop = n_fft // 2
    frames = np.lib.stride_tricks.sliding_window_view(x, n_fft)[::hop]
    if len(frames) > 2000:
        frames = frames[:: len(frames) // 2000 + 1]
    spectrum = np.fft.rfft(frames * np.hanning(n_fft), axis=1)
    db = 10 * np.log10((np.abs(spectrum) ** 2).mean(axis=0) + 1e-20)
    bin_hz = sr / n_fft
    w = max(3, int(T["cutoff_band_hz"] / bin_hz))
    lo, hi = int(4000 / bin_hz) + w, len(db) - w - 1
    if hi <= lo:
        return None
    cs = np.concatenate([[0.0], np.cumsum(db)])
    ks = np.arange(lo, hi)
    below = (cs[ks] - cs[ks - w]) / w
    above = (cs[ks + w] - cs[ks]) / w
    drop = below - above
    i = int(np.argmax(drop))
    return float(ks[i] * bin_hz), float(drop[i])


def analyze_wav(data: bytes) -> ModuleResult:
    x, sr = _read_wav(data)
    duration = len(x) / sr
    findings: list[Finding] = []
    notes = [
        "Thresholds are uncalibrated placeholders; treat as a triage signal only.",
    ]
    evidence: dict = {"format": "wav", "sample_rate": sr, "duration_s": round(duration, 2)}

    if float(np.sqrt(np.mean(x**2))) < 1e-4:
        notes.append("Audio is silent or near-silent; no analysis was possible.")
    elif len(x) < T["n_fft"] * 4:
        notes.append("Audio is too short (under ~0.2 s at 44.1 kHz) for a reliable spectrum.")
    elif sr / 2 < 8500:
        notes.append(
            f"Sample rate {sr} Hz has no content above 8 kHz, so the vocoder-cutoff check "
            "could not be applied."
        )
    else:
        found = find_cutoff(x, sr)
        if found:
            fc, drop = found
            evidence.update({"cutoff_hz": round(fc), "cutoff_drop_db": round(drop, 1)})
            if drop >= T["cutoff_drop_db"]:
                params = {"cutoff_khz": f"{fc / 1000:.1f}", "drop_db": f"{drop:.0f}"}
                if 7500 <= fc <= 8500:
                    findings.append(Finding("wav_vocoder_cutoff", 30, params))
                else:
                    findings.append(Finding("wav_bandlimited", 10, params))
    return ModuleResult("deepfake", findings, evidence, notes)


def analyze(data: bytes) -> ModuleResult:
    fmt = sniff_format(data)
    return analyze_wav(data) if fmt == "wav" else analyze_image(data, fmt)
