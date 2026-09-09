import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Container-friendly production output: `npm run build` also emits
  // .next/standalone/server.js. The Docker runtime uses `npm start`;
  // the standalone bundle is verified bootable (see deployment docs).
  output: "standalone",
};

export default nextConfig;
