/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./templates/**/*.html",
    "./static/js/**/*.js",
  ],
  // Dark mode opt-in : active via la classe `dark` sur <html>.
  // Page `/settings` → Apparence → Clair/Sombre/Système.
  darkMode: 'class',
  // Safelist : classes générées dynamiquement via interpolation Jinja
  // (ex: md:col-span-{{ w['col_span'] }}). Le JIT de Tailwind ne peut pas
  // voir les valeurs interpolées — on les déclare explicitement.
  safelist: [
    "dark",
    "col-span-1", "col-span-2", "col-span-3", "col-span-4",
    "col-span-5", "col-span-6", "col-span-7", "col-span-8",
    "col-span-9", "col-span-10", "col-span-11", "col-span-12",
    "md:col-span-1", "md:col-span-2", "md:col-span-3", "md:col-span-4",
    "md:col-span-5", "md:col-span-6", "md:col-span-7", "md:col-span-8",
    "md:col-span-9", "md:col-span-10", "md:col-span-11", "md:col-span-12",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"DM Sans"', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'Helvetica Neue', 'sans-serif']
      },
      colors: {
        // Palette brand pilotée par CSS variables → adaptative light/dark.
        // Définitions :root et .dark dans tailwind-input.css.
        // Format `R G B` (espaces) requis par Tailwind 3.3+ syntax avec <alpha-value>.
        brand: {
          50:  'rgb(var(--brand-50)  / <alpha-value>)',
          100: 'rgb(var(--brand-100) / <alpha-value>)',
          200: 'rgb(var(--brand-200) / <alpha-value>)',
          300: 'rgb(var(--brand-300) / <alpha-value>)',
          400: 'rgb(var(--brand-400) / <alpha-value>)',
          500: 'rgb(var(--brand-500) / <alpha-value>)',
          600: 'rgb(var(--brand-600) / <alpha-value>)',
          700: 'rgb(var(--brand-700) / <alpha-value>)',
          800: 'rgb(var(--brand-800) / <alpha-value>)',
          900: 'rgb(var(--brand-900) / <alpha-value>)',
          950: 'rgb(var(--brand-950) / <alpha-value>)'
        }
      }
    }
  },
  plugins: [],
}
