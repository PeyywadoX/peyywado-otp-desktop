const SoundFX = (() => {
  let ctx = null;
  let bus = null;
  let enabled = true;

  function ensure() {
    if (!enabled) return null;
    if (!ctx) {
      const AC = window.AudioContext || window.webkitAudioContext;
      if (!AC) return null;
      ctx = new AC();
      const comp = ctx.createDynamicsCompressor();
      comp.threshold.setValueAtTime(-10, ctx.currentTime);
      comp.knee.setValueAtTime(12, ctx.currentTime);
      comp.ratio.setValueAtTime(6, ctx.currentTime);
      comp.attack.setValueAtTime(0.003, ctx.currentTime);
      comp.release.setValueAtTime(0.12, ctx.currentTime);

      const master = ctx.createGain();
      master.gain.setValueAtTime(1.15, ctx.currentTime);

      comp.connect(master);
      master.connect(ctx.destination);
      bus = comp;
    }
    if (ctx.state === 'suspended') {
      ctx.resume().catch(() => {});
    }
    return ctx;
  }

  function tone(freq, dur, type = 'sine', vol = 0.24, delay = 0, freqEnd = null, attack = 0.006) {
    const c = ensure();
    if (!c || !bus) return;
    const t0 = c.currentTime + delay;
    const osc = c.createOscillator();
    const gain = c.createGain();
    osc.type = type;
    osc.frequency.setValueAtTime(freq, t0);
    if (freqEnd !== null) {
      osc.frequency.exponentialRampToValueAtTime(Math.max(20, freqEnd), t0 + dur);
    }
    gain.gain.setValueAtTime(0.0001, t0);
    gain.gain.linearRampToValueAtTime(vol, t0 + attack);
    gain.gain.exponentialRampToValueAtTime(0.0001, t0 + dur);
    osc.connect(gain);
    gain.connect(bus);
    osc.start(t0);
    osc.stop(t0 + dur + 0.02);
  }

  return {
    setEnabled(v) { enabled = !!v; },
    isEnabled() { return enabled; },
    copy() {
      tone(880, 0.09, 'triangle', 0.28, 0, 1174.66, 0.004);
      tone(1318.51, 0.14, 'sine', 0.26, 0.055, 1760, 0.005);
      tone(2637.02, 0.11, 'sine', 0.10, 0.06, null, 0.004);
    },
    click() {
      tone(660, 0.045, 'triangle', 0.18, 0, 440, 0.003);
      tone(1320, 0.028, 'sine', 0.08, 0, 880, 0.002);
    },
    rollover() {
      tone(587.33, 0.09, 'triangle', 0.18, 0, 880, 0.005);
      tone(1174.66, 0.12, 'sine', 0.14, 0.055, null, 0.005);
    },
    sync() {
      tone(587.33, 0.11, 'triangle', 0.28, 0);
      tone(783.99, 0.12, 'triangle', 0.30, 0.075);
      tone(1046.50, 0.15, 'triangle', 0.32, 0.15);
      tone(1567.98, 0.28, 'sine', 0.34, 0.22);
      tone(783.99, 0.26, 'sine', 0.16, 0.22);
    },
    error() {
      tone(260, 0.13, 'sawtooth', 0.24, 0, 175, 0.004);
      tone(195, 0.20, 'sawtooth', 0.28, 0.13, 125, 0.004);
      tone(130, 0.20, 'triangle', 0.20, 0.13, 95, 0.004);
    }
  };
})();
window.SoundFX = SoundFX;
