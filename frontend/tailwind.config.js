/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],

  theme: {
    extend: {
      colors: {
        background: "#0B1020",
        card: "#121A2B",
        border: "#1F2937",

        success: "#22c55e",
        warning: "#f59e0b",
        danger: "#ef4444",
        info: "#3b82f6",

        neon: "#00ffcc",
      },

      boxShadow: {
        neon: "0 0 20px rgba(0,255,204,0.3)",
      }
    },
  },

  plugins: [],
}