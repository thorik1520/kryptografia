package kryptografia_z2_3;

import java.math.BigInteger;
import java.security.SecureRandom;

public class MyThread extends Thread {
	BigInteger prime;
	int bitLength;
	SecureRandom random;
	
	public MyThread(int bitLength, SecureRandom random) {
		this.bitLength = bitLength;
		this.random = random;
	}
	
	public void run() {
		prime = BigInteger.probablePrime(bitLength, random);
    }
	
	public BigInteger getPrime() {
		return prime;
	}
}
