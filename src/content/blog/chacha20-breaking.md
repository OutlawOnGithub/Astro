---
author: Lucas P.
pubDatetime: 2024-07-08T17:41:30Z
#modDatetime: 2023-12-21T09:12:47.400Z
title: Known-plaintext attack with key+nonce reuse on ChaCha20
slug: chacha20-breaking
featured: true
draft: false
tags:
  - cryptography
  - chacha20
  - xor
description:
  How to crack a ChaCha20 ciphertext under some conditions  
---
## Table of Contents

## How Does ChaCha20 Work?
ChaCha20 is a stream cipher designed by Daniel J. Bernstein in 2008, known for its high performance and security.

It operates by generating a pseudorandom stream of bits (the _keystream_) derived from the key and a nonce (supposedly used _once_). This keystream, as long as the plaintext, is then XORed with the plaintext to produce the ciphertext.

Pretty simple, right?

## The challenge
In this example we have the following code :
```python
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
from secret import FLAG

def encrypt(msg, key, iv):
    cipher = ChaCha20.new(key=key, nonce=iv)
    ciphertext = cipher.encrypt(msg.encode())  # Encode string to bytes
    return ciphertext

msg = "Hey agent, heres a secret message for you :"
key = get_random_bytes(32)  # 256-bit key for ChaCha20
iv = get_random_bytes(12)   # 96-bit IV for ChaCha20

encrypted_message = encrypt(msg, key, iv)
encrypted_flag = encrypt(FLAG, key, iv)

encrypted_flag = encrypt(FLAG, key, iv)
print(iv.hex() + "\n" + encrypted_message.hex() + "\n" + encrypted_flag.hex())
```
And the following ciphertext :
```
4a441144b78987964e097222
7f3e729b73d0f526c441ca45b9391be6d823ff1da412e612d23940c462d65ec346940ce84511c969e5bb3f39
71174afc69cea03de608b56fb90e109eec6dae509213f8
```
From the code, we can identify three different parts of the ciphertext :
 - The nonce/IV : `4a441144b78987964e097222`
 - A ciphertext containing known plaintext `7f3e729b73[...]69e5bb3f39`
 - A ciphertext containing the flag `71174afc69cea03de608b56fb90e109eec6dae509213f8`

We observe that both the key and the nonce were generated once but used twice, which is a major security flaw!

## Known-plaintext attack on key+nonce reuse
Since the keystream generation is deterministic, the same keystream was XORed with the plaintext to produce the ciphertext we have.

Given a ciphertext with the corresponding plaintext, we can extract the keystream.

Because XOR is an associative operation, Cipher XOR Plain = KeyStream (where the original operation is KeyStream XOR Plain = Cipher).

This gives us the keystream: `375b0bbb12b79048b06dea2ddc4b7ec1ab039e3dd77785` (shortened for brevity, matching the length of the encrypted flag).

XORing this keystream with the encrypted flag uncovers the flag! TADAAA

## Suggested Implementation to Break a ChaCha20 Cipher

```python
iv = "4a441144b78987964e097222"
plaintext = "Hey agent, here's a secret message for you :"
encrypted_plaintext = "7f3e729b73d0f526c441ca45b9391be6d823ff1da412e612d23940c462d65ec346940ce84511c969e5bb3f39"
flag = "71174afc69cea03de608b56fb90e109eec6dae509213f8"

def xor_bytes(bytes1, bytes2):
   
    # Perform XOR byte by byte
    result = bytes([a ^ b for a, b in zip(bytes1, bytes2)])
    
    return result

plaintext_bytes = plaintext.encode('utf-8')
cipher_bytes = bytes.fromhex(encrypted_plaintext)
flag_bytes = bytes.fromhex(flag)

# Ensure the length matches that of 'flag'
short_keystream = xor_bytes(cipher_bytes[:len(flag_bytes)], plaintext_bytes[:len(flag_bytes)])

finalxor = xor_bytes(flag_bytes, short_keystream)
print(finalxor.decode('utf-8'))
```

Thank you for reading through to the end! Have a wonderful day :)