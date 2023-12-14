package com.rsa.encryption.decryption.controller;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.rsa.encryption.decryption.service.RSAService;

@RestController
@RequestMapping("/api/rsa")
public class RSAController {

	@Autowired
	private RSAService rsaService;

	@GetMapping("/encrypt")
	public String encrypt(@RequestParam String plaintext) throws Exception {
		KeyPair keyPair = rsaService.generateRSAKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		return rsaService.encrypt(plaintext, publicKey);
	}

	@GetMapping("/decrypt")
	public String decrypt(@RequestParam String ciphertext) throws Exception {
		KeyPair keyPair = rsaService.generateRSAKeyPair(); // In a real scenario, use a securely stored key pair
		PrivateKey privateKey = keyPair.getPrivate();
		return rsaService.decrypt(ciphertext, privateKey);
	}
}
