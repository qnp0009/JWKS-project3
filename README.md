# JWKS Server Implementation

A secure FastAPI-based JSON Web Key Set (JWKS) server with user registration and authentication features.

## Features

- 🔒 AES-encrypted private key storage
- 🔑 JWKS endpoint at `/.well-known/jwks.json`
- 👤 User registration with auto-generated passwords
- 📝 Authentication request logging
- ⏱️ Rate limiting (10 requests/second)
- 🛡️ Secure password hashing with Argon2

## Tech Stack

- Python 3.8+
- FastAPI
- SQLite
- JOSE (JWT implementation)
- Cryptography (AES/RSA operations)

## Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/YOUR-USERNAME/jwks-server.git
   cd jwks-server
