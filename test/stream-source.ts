// A 1 MB length-less request body, pulled on demand, recording how many bytes were read from it and
// whether it was cancelled — the probe for camada-all-4u4i's "cap + one chunk" bound.
export const CHUNK = 1024;
export function streamSource() {
  const s = { pulled: 0, cancelled: false, stream: null as unknown as ReadableStream<Uint8Array> };
  let sent = 0;
  s.stream = new ReadableStream<Uint8Array>({
    pull(ctrl) {
      if (sent++ >= 1024) { ctrl.close(); return; }
      s.pulled += CHUNK;
      ctrl.enqueue(new Uint8Array(CHUNK).fill(0x78));
    },
    cancel() { s.cancelled = true; },
  }, { highWaterMark: 0 });
  return s;
}
