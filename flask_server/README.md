# AES Crypto Tool - Flask Backend

This is the backend API server for the AES Crypto Tool, providing encryption and decryption endpoints.

## Features

- **AES Encryption/Decryption**: Support for ECB and CBC modes
- **Multiple Key Sizes**: 128, 192, and 256-bit keys
- **Padding Options**: PKCS7, Zero Padding, and No Padding
- **Key/IV Generation**: Generate cryptographically secure random keys and IVs
- **CORS Enabled**: Works seamlessly with frontend applications
- **Input Validation**: Comprehensive validation and error handling
- **Logging**: Detailed logging for debugging and monitoring

## Installation

1. **Create a virtual environment** (recommended):
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

## Running the Server

### Option 1: Using run.py (Recommended)
```bash
python run.py
```

### Option 2: Using app.py directly
```bash
python app.py
```

### Option 3: Using Flask CLI
```bash
export FLASK_APP=app.py  # On Windows: set FLASK_APP=app.py
flask run
```

The server will start at `http://localhost:5000` by default.

## API Endpoints

### Health Check
```http
GET /health
```

### Encrypt Data
```http
POST /encrypt
Content-Type: application/json

{
  "plaintext": "Hello, World!",
  "mode": "CBC",
  "padding": "PKCS7",
  "key_size": 256,
  "key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "iv": "0123456789abcdef0123456789abcdef"
}
```

### Decrypt Data
```http
POST /decrypt
Content-Type: application/json

{
  "ciphertext": "encrypted_hex_data_here",
  "mode": "CBC",
  "padding": "PKCS7",
  "key_size": 256,
  "key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "iv": "0123456789abcdef0123456789abcdef"
}
```

### Generate Random Key
```http
POST /generate-key
Content-Type: application/json

{
  "key_size": 256
}
```

### Generate Random IV
```http
POST /generate-iv
```

## Configuration

Environment variables:
- `PORT`: Server port (default: 5000)
- `HOST`: Server host (default: 127.0.0.1)
- `DEBUG`: Enable debug mode (default: True)

## Supported Parameters

### Modes
- `ECB`: Electronic Codebook mode
- `CBC`: Cipher Block Chaining mode (requires IV)

### Key Sizes
- `128`: 128-bit key (32 hex characters)
- `192`: 192-bit key (48 hex characters)  
- `256`: 256-bit key (64 hex characters)

### Padding
- `PKCS7`: PKCS#7 padding (recommended)
- `ZEROPADDING`: Zero byte padding
- `NOPADDING`: No padding (data must be block-aligned)

## Security Notes

⚠️ **Important Security Considerations:**

1. **This tool is for educational/testing purposes**
2. **Never use ECB mode in production** - it's cryptographically weak
3. **Always use random IVs** for CBC mode
4. **Keep keys secure** - never log or expose them
5. **Use HTTPS** in production environments
6. **Validate all inputs** - this API does basic validation but additional checks may be needed

## Error Handling

The API returns detailed error messages for:
- Invalid hex format
- Wrong key/IV lengths
- Unsupported modes/padding
- Invalid ciphertext
- Padding errors

## Dependencies

- `Flask`: Web framework
- `Flask-CORS`: Cross-origin resource sharing
- `pycryptodome`: Cryptographic library

## Troubleshooting

### Common Issues

1. **ModuleNotFoundError**: Install dependencies with `pip install -r requirements.txt`
2. **Port already in use**: Change the port using `PORT=5001 python run.py`
3. **CORS errors**: Make sure Flask-CORS is installed and working
4. **Crypto errors**: Ensure pycryptodome is installed (not pycrypto)

### Testing the API

Use curl to test endpoints:

```bash
# Health check
curl http://localhost:5000/health

# Generate a key
curl -X POST http://localhost:5000/generate-key \
  -H "Content-Type: application/json" \
  -d '{"key_size": 256}'

# Encrypt data
curl -X POST http://localhost:5000/encrypt \
  -H "Content-Type: application/json" \
  -d '{
    "plaintext": "Hello, World!",
    "mode": "ECB",
    "padding": "PKCS7",
    "key_size": 128,
    "key": "0123456789abcdef0123456789abcdef"
  }'
```