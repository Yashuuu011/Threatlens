/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: "#090d16",
          surface: "#0f1623",
          elevated: "#151f32",
          border: "#1e2c45",
          accent: "#06b6d4",
          electric: "#3b82f6",
          critical: "#ef4444",
          high: "#f97316",
          medium: "#eab308",
          healthy: "#10b981",
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      }
    },
  },
  plugins: [],
}

