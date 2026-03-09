import init, { solve } from "../pkg/challenge_wasm.js";

let wasmReady = false;

self.onmessage = async (e) => {
  const { workerId, randomData, difficulty, startNonce, step } = e.data;

  // Initialize WASM if not already done.
  if (!wasmReady) {
    await init();
    wasmReady = true;
  }

  // Signal that we're ready.
  self.postMessage({ type: "ready", workerId });

  // Run the solver.
  const result = solve(
    randomData,
    difficulty,
    BigInt(startNonce),
    BigInt(step),
  );

  // Parse result: first 8 bytes = nonce (big-endian), rest = hash.
  // ________________________
  // |         40 bytes     |
  // ------------------------
  // |  8 bytes  | 32 bytes |
  // ------------------------
  // |   nonce   |  hash    |
  // ------------------------
  const nonceBytes = result.slice(0, 8);
  const nonce = new DataView(nonceBytes.buffer).getBigUint64(0, false);
  const hash = result.slice(8);

  // Send solution back
  self.postMessage({
    type: "found",
    workerId,
    nonce: nonce.toString(),
    hash: Array.from(hash),
  });
};
