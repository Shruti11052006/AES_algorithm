from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Helper function for padding selection
def apply_padding(data, block_size, padding_type):
    """Apply the specified padding to data"""
    try:
        if padding_type.upper() == "PKCS7":
            return pad(data, block_size)
        elif padding_type.upper() == "ZEROPADDING":
            padding_len = block_size - (len(data) % block_size)
            if padding_len == block_size:
                padding_len = 0  # No padding needed if already aligned
            return data + b"\x00" * padding_len
        elif padding_type.upper() == "NOPADDING":
            if len(data) % block_size != 0:
                raise ValueError("Data length must be multiple of block size for no padding")
            return data
        else:
            raise ValueError(f"Invalid padding type: {padding_type}")
    except Exception as e:
        logger.error(f"Padding error: {str(e)}")
        raise

def remove_padding(data, block_size, padding_type):
    """Remove the specified padding from data"""
    try:
        if padding_type.upper() == "PKCS7":
            return unpad(data, block_size)
        elif padding_type.upper() == "ZEROPADDING":
            return data.rstrip(b"\x00")
        elif padding_type.upper() == "NOPADDING":
            return data
        else:
            raise ValueError(f"Invalid padding type: {padding_type}")
    except Exception as e:
        logger.error(f"Unpadding error: {str(e)}")
        raise

def validate_hex_key(key_hex, expected_length):
    """Validate hex key format and length"""
    if not key_hex:
        raise ValueError("Key cannot be empty")
    
    try:
        key_bytes = bytes.fromhex(key_hex)
    except ValueError:
        raise ValueError("Key must be valid hexadecimal")
    
    if len(key_bytes) != expected_length:
        raise ValueError(f"Key must be {expected_length} bytes ({expected_length * 2} hex characters)")
    
    return key_bytes

def validate_hex_iv(iv_hex):
    """Validate hex IV format and length"""
    if not iv_hex:
        raise ValueError("IV cannot be empty for CBC mode")
    
    try:
        iv_bytes = bytes.fromhex(iv_hex)
    except ValueError:
        raise ValueError("IV must be valid hexadecimal")
    
    if len(iv_bytes) != 16:  # AES block size is always 16 bytes
        raise ValueError("IV must be 16 bytes (32 hex characters)")
    
    return iv_bytes

def validate_hex_data(data_hex):
    """Validate hex data format"""
    if not data_hex:
        raise ValueError("Data cannot be empty")
    
    try:
        return bytes.fromhex(data_hex)
    except ValueError:
        raise ValueError("Data must be valid hexadecimal")

# Health check endpoint
@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "message": "AES Crypto API is running",
        "version": "1.0.0"
    })

# Generate random key endpoint
@app.route("/generate-key", methods=["POST"])
def generate_key():
    """Generate a random AES key"""
    try:
        data = request.json or {}
        key_size = int(data.get("key_size", 128))
        
        if key_size not in [128, 192, 256]:
            return jsonify({"error": "Key size must be 128, 192, or 256 bits"}), 400
        
        key_bytes = get_random_bytes(key_size // 8)
        
        return jsonify({
            "key": key_bytes.hex(),
            "key_size": key_size,
            "length_bytes": len(key_bytes),
            "length_hex": len(key_bytes.hex())
        })
    
    except Exception as e:
        logger.error(f"Key generation error: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Generate random IV endpoint
@app.route("/generate-iv", methods=["POST"])
def generate_iv():
    """Generate a random IV for CBC mode"""
    try:
        iv_bytes = get_random_bytes(16)  # AES block size is always 16 bytes
        
        return jsonify({
            "iv": iv_bytes.hex(),
            "length_bytes": 16,
            "length_hex": 32
        })
    
    except Exception as e:
        logger.error(f"IV generation error: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Encryption endpoint
@app.route("/encrypt", methods=["POST"])
def encrypt():
    """Encrypt plaintext using AES"""
    try:
        data = request.json
        if not data:
            return jsonify({"error": "Request body must be JSON"}), 400
        
        # Extract parameters
        plaintext = data.get("plaintext")
        mode = data.get("mode", "ECB").upper()
        padding_type = data.get("padding", "PKCS7").upper()
        key_size = int(data.get("key_size", 128))
        key_hex = data.get("key")
        iv_hex = data.get("iv")
        
        # Validation
        if not plaintext:
            return jsonify({"error": "Plaintext is required"}), 400
        
        if mode not in ["ECB", "CBC"]:
            return jsonify({"error": "Mode must be ECB or CBC"}), 400
        
        if padding_type not in ["PKCS7", "ZEROPADDING", "NOPADDING"]:
            return jsonify({"error": "Padding must be PKCS7, ZEROPADDING, or NOPADDING"}), 400
        
        if key_size not in [128, 192, 256]:
            return jsonify({"error": "Key size must be 128, 192, or 256 bits"}), 400
        
        # Validate key
        expected_key_length = key_size // 8
        key_bytes = validate_hex_key(key_hex, expected_key_length)
        
        # Convert plaintext to bytes
        plaintext_bytes = plaintext.encode('utf-8')
        
        # Create cipher based on mode
        if mode == "ECB":
            cipher = AES.new(key_bytes, AES.MODE_ECB)
        elif mode == "CBC":
            iv_bytes = validate_hex_iv(iv_hex)
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        
        # Apply padding
        padded_data = apply_padding(plaintext_bytes, AES.block_size, padding_type)
        
        # Encrypt
        ciphertext = cipher.encrypt(padded_data)
        
        logger.info(f"Encryption successful - Mode: {mode}, Padding: {padding_type}, Key Size: {key_size}")
        
        return jsonify({
            "ciphertext": ciphertext.hex(),
            "mode": mode,
            "padding": padding_type,
            "key_size": key_size,
            "ciphertext_length": len(ciphertext.hex())
        })
    
    except ValueError as e:
        logger.warning(f"Validation error in encryption: {str(e)}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Encryption error: {str(e)}")
        return jsonify({"error": f"Encryption failed: {str(e)}"}), 500

# Decryption endpoint
@app.route("/decrypt", methods=["POST"])
def decrypt():
    """Decrypt ciphertext using AES"""
    try:
        data = request.json
        if not data:
            return jsonify({"error": "Request body must be JSON"}), 400
        
        # Extract parameters
        ciphertext_hex = data.get("ciphertext")
        mode = data.get("mode", "ECB").upper()
        padding_type = data.get("padding", "PKCS7").upper()
        key_size = int(data.get("key_size", 128))
        key_hex = data.get("key")
        iv_hex = data.get("iv")
        
        # Validation
        if not ciphertext_hex:
            return jsonify({"error": "Ciphertext is required"}), 400
        
        if mode not in ["ECB", "CBC"]:
            return jsonify({"error": "Mode must be ECB or CBC"}), 400
        
        if padding_type not in ["PKCS7", "ZEROPADDING", "NOPADDING"]:
            return jsonify({"error": "Padding must be PKCS7, ZEROPADDING, or NOPADDING"}), 400
        
        if key_size not in [128, 192, 256]:
            return jsonify({"error": "Key size must be 128, 192, or 256 bits"}), 400
        
        # Validate inputs
        expected_key_length = key_size // 8
        key_bytes = validate_hex_key(key_hex, expected_key_length)
        ciphertext_bytes = validate_hex_data(ciphertext_hex)
        
        # Check if ciphertext length is valid for block cipher
        if len(ciphertext_bytes) % AES.block_size != 0:
            return jsonify({"error": "Ciphertext length must be multiple of block size (16 bytes)"}), 400
        
        # Create cipher based on mode
        if mode == "ECB":
            cipher = AES.new(key_bytes, AES.MODE_ECB)
        elif mode == "CBC":
            iv_bytes = validate_hex_iv(iv_hex)
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        
        # Decrypt
        decrypted_data = cipher.decrypt(ciphertext_bytes)
        
        # Remove padding
        plaintext_bytes = remove_padding(decrypted_data, AES.block_size, padding_type)
        
        # Convert to string (handle potential encoding issues)
        try:
            plaintext = plaintext_bytes.decode('utf-8')
        except UnicodeDecodeError:
            # If UTF-8 decoding fails, try with error handling
            plaintext = plaintext_bytes.decode('utf-8', errors='replace')
            logger.warning("Decryption resulted in non-UTF-8 data, some characters may be replaced")
        
        logger.info(f"Decryption successful - Mode: {mode}, Padding: {padding_type}, Key Size: {key_size}")
        
        return jsonify({
            "plaintext": plaintext,
            "mode": mode,
            "padding": padding_type,
            "key_size": key_size,
            "plaintext_length": len(plaintext)
        })
    
    except ValueError as e:
        logger.warning(f"Validation error in decryption: {str(e)}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("DEBUG", "True").lower() == "true"
    
    logger.info(f"Starting AES Crypto API server on port {port}")
    logger.info(f"Debug mode: {debug}")
    
    app.run(
        host="0.0.0.0",
        port=port,
        debug=debug
    )