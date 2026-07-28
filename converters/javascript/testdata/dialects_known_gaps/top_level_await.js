// Top-level await is only expressible in ES-module output, and goja reads
// CommonJS, so esbuild cannot lower this for us: "Top-level await is currently
// not supported with the cjs output format". Neither iife nor cjs accepts it;
// only esm does, which the lowering cannot consume. Tracked, not silently lost.
export const config = await Promise.resolve({ debug: true });
