/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./templates/**/*.html", // 确保 TailwindCSS 处理 Flask 模板
    "./static/**/*.js",      // 如果有静态的 JavaScript 文件
  ],
  theme: {
    extend: {},
  },
  plugins: [],
};

