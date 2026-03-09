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

  // Send solution back
  self.postMessage({
    type: "found",
    workerId,
    nonce: result.toString(),
  });
};
