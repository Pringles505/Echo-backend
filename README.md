<h1 align="center">
  <picture>
    <!-- Dark mode logo -->
    <source 
      srcset="logoTextDark.png" 
      media="(prefers-color-scheme: dark)"
      width="300" 
      height="130"
    >
    <!-- Light mode logo -->
    <img 
      src="logoTextLight.png" 
      alt="Echo Logo" 
      width="300" 
      height="130"
    >
  </picture>
</h1>

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Built_with-Rust-orange.svg)](https://www.rust-lang.org/)
[![WASM](https://img.shields.io/badge/Powered_by-WebAssembly-purple.svg)](https://webassembly.org/)

# What is Echo?

Echo is a secure chat app with a security protocol based on the [**Signal Protocol**](https://signal.org/docs/). Built with minimal external library use, all **Diffie Hellman Operations** including **Scalar Multiplication** are powered by our own Rust modules compiled with **WebAssembly** for the WebApp.

