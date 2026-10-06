/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        base: '#0E1013',
        surface: '#161A1F',
        hairline: '#262C34',
        accent: '#F2B84B',
        severity: {
          low: '#4FA36B',
          medium: '#D9A441',
          high: '#E2793B',
          critical: '#D64545',
        }
      },
      fontFamily: {
        display: ['"Fraunces Variable"', 'serif'],
        sans: ['"Instrument Sans Variable"', 'sans-serif'],
        mono: ['"JetBrains Mono Variable"', 'monospace'],
      },
      letterSpacing: {
        widest: '.08em',
      }
    },
  },
  plugins: [],
}
