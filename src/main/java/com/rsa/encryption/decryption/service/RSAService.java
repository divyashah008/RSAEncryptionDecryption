package com.rsa.encryption.decryption.service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;

import org.springframework.stereotype.Service;

@Service
public class RSAService {

	public String encrypt(String plaintext, PublicKey publicKey) throws Exception {
		// Get an RSA cipher object
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);

		// Encrypt the plaintext
		byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
		return Base64.getEncoder().encodeToString(encryptedBytes);
	}

	public String decrypt(String ciphertext, PrivateKey privateKey) throws Exception {
		// Get an RSA cipher object
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);

		// Decrypt the ciphertext
		byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
		return new String(decryptedBytes);
	}

	public KeyPair generateRSAKeyPair() throws Exception {
		// Generate an RSA key pair
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048); // You can use other key sizes, such as 1024 or 4096
		return keyPairGenerator.generateKeyPair();
	}
}
