import hmac
import hashlib
import json

def verify_webhook_signature(payload, signature, secret):
    """
    Verify webhook signature using HMAC SHA256.
    
    Args:
        payload: The webhook payload dict
        signature: The X-Webhook-Signature header value
        secret: Your webhook secret
        
    Returns:
        bool: True if signature is valid, False otherwise
    """
    expected_signature = hmac.new(
        secret.encode('utf-8'),
        json.dumps(payload, separators=(',', ':')).encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(signature, expected_signature)
