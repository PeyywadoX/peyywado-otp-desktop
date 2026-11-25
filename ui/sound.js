const SoundFX = (() => {
  let ctx = null;
  let enabled = true;

  function ensure() {
    if (!enabled) return null;
    if (!ctx) {
      const AC = window.AudioContext || window.webkitAudioContext;
      if (!AC) return null;
      ctx = new AC();
    }
    if (ctx.state === 'suspended') {
      ctx.resume().catch(() => {});
    }
    return ctx;
  }

  function tone(freq, dur, type = 'sine', vol = 0.05, delay = 0, freqEnd = null) {
    const c = ensure();
    if (!c) return;
    const t0 = c.currentTime + delay;
    const osc = c.createOscillator();
    const gain = c.createGain();
    osc.type = type;
    osc.frequency.setValueAtTime(freq, t0);
    if (freqEnd !== null) {
      osc.frequency.exponentialRampToValueAtTime(freqEnd, t0 + dur);
    }
    gain.gain.setValueAtTime(0.0001, t0);
    gain.gain.exponentialRampToValueAtTime(vol, t0 + 0.008);
    gain.gain.exponentialRampToValueAtTime(0.0001, t0 + dur);
    osc.connect(gain);
    gain.connect(c.destination);
    osc.start(t0);
    osc.stop(t0 + dur + 0.01);
  }

  return {
    setEnabled(v) { enabled = !!v; },
    isEnabled() { return enabled; },
    copy() {
      tone(740, 0.06, 'triangle', 0.055, 0, 920);
      tone(1180, 0.09, 'sine', 0.045, 0.045, 1320);
    },
    click() {
      tone(520, 0.035, 'triangle', 0.03, 0, 380);
    },
    rollover() {
      tone(440, 0.05, 'sine', 0.028, 0, 620);
    },
    sync() {
      tone(523.25, 0.09, 'sine', 0.045, 0);
      tone(659.25, 0.09, 'sine', 0.045, 0.07);
      tone(783.99, 0.14, 'sine', 0.05, 0.14);
    },
    error() {
      tone(220, 0.11, 'sawtooth', 0.035, 0, 155);
    }
  };
})();
window.SoundFX = SoundFX;
