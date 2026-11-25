/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        obsidian: {
          950: "#07090d",
          900: "#0c1017",
          850: "#111620",
          800: "#161d2b",
          700: "#1f293b",
          600: "#2e3c54",
        },
        signal: {
          cyan: "#38bdf8",
          emerald: "#34d399",
          amber: "#fbbf24",
          rose: "#fb7185",
          violet: "#a78bfa",
        },
      },
      fontFamily: {
        sans: [
          "Inter",
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "Segoe UI",
          "Roboto",
          "sans-serif",
        ],
        mono: [
          "JetBrains Mono",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Consolas",
          "monospace",
        ],
      },
    },
  },
  plugins: [],
};
