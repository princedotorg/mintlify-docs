package main

import (
    "crypto/hmac"
    "crypto/sha256"
    "crypto/subtle"
    "encoding/hex"
    "encoding/json"
)

func VerifyWebhookSignature(payload interface{}, signature string, secret string) bool {
    payloadBytes, err := json.Marshal(payload)
    if err != nil {
        return false
    }

    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write(payloadBytes)
    expectedSignature := hex.EncodeToString(mac.Sum(nil))

    return subtle.ConstantTimeCompare([]byte(signature), []byte(expectedSignature)) == 1
}
