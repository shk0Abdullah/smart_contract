module.exports = {
    content: [
        '../templates/**/*.html',
        '../../templates/**/*.html',
        '../../**/templates/**/*.html',
        // '../../**/*.js',
        // '../../**/*.py',
    ],
    theme: {
        extend: {
            keyframes: {
              diagonal: {
                '0%': { transform: 'translate(-100%, -100%)' },
                '100%': { transform: 'translate(400%, 400%)' },
              },
            },
            animation: {
              diagonal: 'diagonal 1.5s linear infinite',
            }
          }
    },
    plugins: [
        require('@tailwindcss/forms'),
        require('@tailwindcss/typography'),
        require('@tailwindcss/aspect-ratio'),
        require('daisyui')
    ]
}
