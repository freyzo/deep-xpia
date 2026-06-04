import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  base: "/deep-xpia/",
  build: {
    outDir: "../docs",
    emptyOutDir: true,
  },
});
