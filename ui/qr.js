const MiniQR = (() => {

  const EXP = new Uint8Array(512);
  const LOG = new Uint8Array(256);
  for (let i = 0, x = 1; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];

  function gfMul(a, b) {
    return a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]];
  }

  function rsGenPoly(deg) {
    let p = [1];
    for (let i = 0; i < deg; i++) {
      const next = new Array(p.length + 1).fill(0);
      for (let j = 0; j < p.length; j++) {
        next[j] ^= p[j];
        next[j + 1] ^= gfMul(p[j], EXP[i]);
      }
      p = next;
    }
    return p;
  }

  function rsRemainder(data, ecLen) {
    const gen = rsGenPoly(ecLen);
    const rem = new Uint8Array(ecLen);
    for (const b of data) {
      const factor = b ^ rem[0];
      rem.copyWithin(0, 1);
      rem[ecLen - 1] = 0;
      for (let i = 0; i < ecLen; i++) rem[i] ^= gfMul(gen[i + 1], factor);
    }
    return rem;
  }

  const VERSIONS_M = [
    null,
    [26, 10, 1, []],
    [44, 16, 1, [6, 18]],
    [70, 26, 1, [6, 22]],
    [100, 18, 2, [6, 26]],
    [134, 24, 2, [6, 30]],
    [172, 16, 4, [6, 34]],
    [196, 18, 4, [6, 22, 38]],
    [242, 22, 4, [6, 24, 42]],
    [292, 22, 5, [6, 26, 46]],
    [346, 26, 5, [6, 28, 50]],
    [404, 30, 5, [6, 30, 54]],
    [466, 22, 8, [6, 32, 58]],
  ];

  const MASK_FNS = [
    (r, c) => ((r + c) & 1) === 0,
    (r, _c) => (r & 1) === 0,
    (_r, c) => c % 3 === 0,
    (r, c) => (r + c) % 3 === 0,
    (r, c) => (((r >>> 1) + Math.floor(c / 3)) & 1) === 0,
    (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
    (r, c) => ((((r * c) % 2) + ((r * c) % 3)) & 1) === 0,
    (r, c) => ((((r + c) % 2) + ((r * c) % 3)) & 1) === 0,
  ];

  function applyFormatBits(mod, size, eccIndicator, mask) {

    const fmtData = (eccIndicator << 3) | mask;
    let fmtRem = fmtData << 10;
    for (let i = 14; i >= 10; i--) {
      if ((fmtRem >>> i) & 1) fmtRem ^= 0x537 << (i - 10);
    }
    const fmtBits = ((fmtData << 10) | fmtRem) ^ 0x5412;
    const fbit = (idx) => (((fmtBits >>> (14 - idx)) & 1) !== 0 ? 1 : -1);

    for (let i = 0; i <= 5; i++) mod[8][i] = fbit(i);
    mod[8][7] = fbit(6);
    mod[8][8] = fbit(7);
    mod[7][8] = fbit(8);
    for (let i = 0; i <= 5; i++) mod[5 - i][8] = fbit(9 + i);

    for (let i = 0; i < 7; i++) mod[size - 1 - i][8] = fbit(i);

    for (let i = 0; i < 8; i++) mod[8][size - 8 + i] = fbit(7 + i);
  }

  function calcPenalty(mod, size) {
    let pen = 0;

    for (let r = 0; r < size; r++) {
      let runCol = 1;
      let runRow = 1;
      for (let c = 1; c < size; c++) {
        if (mod[r][c] === mod[r][c - 1]) {
          runRow++;
          if (runRow === 5) pen += 3;
          else if (runRow > 5) pen += 1;
        } else {
          runRow = 1;
        }
        if (mod[c][r] === mod[c - 1][r]) {
          runCol++;
          if (runCol === 5) pen += 3;
          else if (runCol > 5) pen += 1;
        } else {
          runCol = 1;
        }
      }
    }

    for (let r = 0; r < size - 1; r++) {
      for (let c = 0; c < size - 1; c++) {
        const v = mod[r][c];
        if (v === mod[r][c + 1] && v === mod[r + 1][c] && v === mod[r + 1][c + 1]) {
          pen += 3;
        }
      }
    }

    const isPat = (arr, i) => {
      const a =
        arr[i] === 1 && arr[i + 1] === -1 && arr[i + 2] === 1 && arr[i + 3] === 1 &&
        arr[i + 4] === 1 && arr[i + 5] === -1 && arr[i + 6] === 1 &&
        arr[i + 7] === -1 && arr[i + 8] === -1 && arr[i + 9] === -1 && arr[i + 10] === -1;
      const b =
        arr[i] === -1 && arr[i + 1] === -1 && arr[i + 2] === -1 && arr[i + 3] === -1 &&
        arr[i + 4] === 1 && arr[i + 5] === -1 && arr[i + 6] === 1 && arr[i + 7] === 1 &&
        arr[i + 8] === 1 && arr[i + 9] === -1 && arr[i + 10] === 1;
      return a || b;
    };
    const colBuf = new Int8Array(size);
    for (let r = 0; r < size; r++) {
      for (let c = 0; c <= size - 11; c++) {
        if (isPat(mod[r], c)) pen += 40;
      }
    }
    for (let c = 0; c < size; c++) {
      for (let r = 0; r < size; r++) colBuf[r] = mod[r][c];
      for (let r = 0; r <= size - 11; r++) {
        if (isPat(colBuf, r)) pen += 40;
      }
    }

    let dark = 0;
    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) if (mod[r][c] === 1) dark++;
    }
    const pct = (dark * 100) / (size * size);
    const k = Math.floor(Math.abs(pct - 50) / 5);
    pen += k * 10;

    return pen;
  }

  function encode(text) {
    const bytes = new TextEncoder().encode(text);
    let ver = 0;
    for (let v = 1; v < VERSIONS_M.length; v++) {
      const [tot, ec, blk] = VERSIONS_M[v];
      const dataCap = tot - ec * blk;
      const hdrBits = 4 + (v >= 10 ? 16 : 8);
      if (Math.ceil((hdrBits + bytes.length * 8) / 8) <= dataCap) {
        ver = v;
        break;
      }
    }
    if (!ver) return null;

    const [totCW, ecPerBlock, numBlocks, align] = VERSIONS_M[ver];
    const dataCW = totCW - ecPerBlock * numBlocks;

    const bits = [];
    const pushBits = (val, len) => {
      for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1);
    };
    pushBits(0b0100, 4);
    pushBits(bytes.length, ver >= 10 ? 16 : 8);
    for (const b of bytes) pushBits(b, 8);
    const maxBits = dataCW * 8;
    for (let i = 0; i < 4 && bits.length < maxBits; i++) bits.push(0);
    while (bits.length % 8 !== 0) bits.push(0);
    const padBytes = [0xec, 0x11];
    let pi = 0;
    while (bits.length < maxBits) {
      pushBits(padBytes[pi++ & 1], 8);
    }

    const rawData = new Uint8Array(dataCW);
    for (let i = 0; i < dataCW; i++) {
      let v = 0;
      for (let b = 0; b < 8; b++) v = (v << 1) | bits[i * 8 + b];
      rawData[i] = v;
    }

    const shortBlocks = numBlocks - (dataCW % numBlocks);
    const shortLen = Math.floor(dataCW / numBlocks);
    const dBlocks = [];
    const eBlocks = [];
    let off = 0;
    for (let i = 0; i < numBlocks; i++) {
      const len = shortLen + (i >= shortBlocks ? 1 : 0);
      const slice = rawData.slice(off, off + len);
      off += len;
      dBlocks.push(slice);
      eBlocks.push(rsRemainder(slice, ecPerBlock));
    }

    const codewords = [];
    for (let i = 0; i < shortLen + 1; i++) {
      for (const db of dBlocks) if (i < db.length) codewords.push(db[i]);
    }
    for (let i = 0; i < ecPerBlock; i++) {
      for (const eb of eBlocks) codewords.push(eb[i]);
    }

    const size = ver * 4 + 17;
    const base = Array.from({ length: size }, () => new Int8Array(size));
    const isFunc = Array.from({ length: size }, () => new Uint8Array(size));

    const setBase = (r, c, dark, fn = false) => {
      if (r < 0 || c < 0 || r >= size || c >= size) return;
      base[r][c] = dark ? 1 : -1;
      if (fn) isFunc[r][c] = 1;
    };

    const drawFinder = (r0, c0) => {
      for (let dr = -1; dr <= 7; dr++) {
        for (let dc = -1; dc <= 7; dc++) {
          const r = r0 + dr, c = c0 + dc;
          if (r < 0 || c < 0 || r >= size || c >= size) continue;
          const on =
            dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6 &&
            (dr === 0 || dr === 6 || dc === 0 || dc === 6 || (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4));
          setBase(r, c, on, true);
        }
      }
    };

    drawFinder(0, 0);
    drawFinder(0, size - 7);
    drawFinder(size - 7, 0);

    for (let i = 8; i < size - 8; i++) {
      setBase(6, i, i % 2 === 0, true);
      setBase(i, 6, i % 2 === 0, true);
    }

    for (let i = 0; i < align.length; i++) {
      for (let j = 0; j < align.length; j++) {
        if ((i === 0 && j === 0) || (i === 0 && j === align.length - 1) || (i === align.length - 1 && j === 0)) continue;
        const cr = align[i], cc = align[j];
        for (let dr = -2; dr <= 2; dr++) {
          for (let dc = -2; dc <= 2; dc++) {
            setBase(cr + dr, cc + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1, true);
          }
        }
      }
    }

    for (let i = 0; i <= 8; i++) {
      if (i !== 6) {
        isFunc[8][i] = 1;
        isFunc[i][8] = 1;
      }
      if (i < 8) {
        isFunc[8][size - 1 - i] = 1;
        isFunc[size - 1 - i][8] = 1;
      }
    }
    setBase(size - 8, 8, true, true);

    if (ver >= 7) {
      let rem = ver;
      for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
      const vbits = (ver << 12) | rem;
      for (let i = 0; i < 18; i++) {
        const dark = ((vbits >>> i) & 1) !== 0;
        const a = size - 11 + (i % 3);
        const b = Math.floor(i / 3);
        setBase(a, b, dark, true);
        setBase(b, a, dark, true);
      }
    }

    const cwBits = [];
    for (const cw of codewords) {
      for (let b = 7; b >= 0; b--) cwBits.push((cw >>> b) & 1);
    }
    let bi = 0;
    for (let right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let vert = 0; vert < size; vert++) {
        for (let j = 0; j < 2; j++) {
          const c = right - j;
          const upward = ((right + 1) & 2) === 0;
          const r = upward ? size - 1 - vert : vert;
          if (!isFunc[r][c]) {
            const bit = bi < cwBits.length ? cwBits[bi++] : 0;
            setBase(r, c, bit === 1, false);
          }
        }
      }
    }

    let bestMod = null;
    let bestPen = Infinity;
    const ECC_M_IND = 0;

    for (let mask = 0; mask < 8; mask++) {
      const mfn = MASK_FNS[mask];
      const cand = base.map((row) => new Int8Array(row));
      for (let r = 0; r < size; r++) {
        for (let c = 0; c < size; c++) {
          if (!isFunc[r][c] && mfn(r, c)) {
            cand[r][c] = -cand[r][c];
          }
        }
      }
      applyFormatBits(cand, size, ECC_M_IND, mask);
      const pen = calcPenalty(cand, size);
      if (pen < bestPen) {
        bestPen = pen;
        bestMod = cand;
      }
    }

    return { size, mod: bestMod };
  }

  function toSVG(text) {
    const qr = encode(text);
    if (!qr) return '';
    const { size, mod } = qr;
    const quiet = 4;
    const dim = size + quiet * 2;
    let d = '';

    for (let r = 0; r < size; r++) {
      let c = 0;
      while (c < size) {
        if (mod[r][c] === 1) {
          const start = c;
          while (c < size && mod[r][c] === 1) c++;
          const run = c - start;
          d += `M${start + quiet},${r + quiet}h${run}v1h-${run}z`;
        } else {
          c++;
        }
      }
    }
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${dim} ${dim}" shape-rendering="crispEdges"><rect width="${dim}" height="${dim}" fill="#ffffff"/><path d="${d}" fill="#000000"/></svg>`;
  }

  return { toSVG, encode };
})();
window.MiniQR = MiniQR;
