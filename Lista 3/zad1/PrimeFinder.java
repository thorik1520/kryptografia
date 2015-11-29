package kryptografia_z1_l3;

import java.math.BigInteger;
import java.security.SecureRandom;

public class PrimeFinder {
	SecureRandom random;
	BigInteger[] primeArr;
	MyThread[] threadArr;
	int primesCount, bitLength;
	
	BigInteger[] getUniquePrimes(int primesCount, int bitLength) throws InterruptedException {
		primeArr = new BigInteger[primesCount];
		threadArr = new MyThread[primesCount];
		
		random = new SecureRandom();
		
		for(int i = 0; i < primesCount; i++) {
			threadArr[i] = new MyThread(bitLength, random);
			threadArr[i].run();
		}
		
		for(int i = 0; i < primesCount; i++) {
			threadArr[i].join();
			primeArr[i] = threadArr[i].getPrime();
		}
		
		boolean unique;
		for(int i = 0; i < primesCount; i++) {
			do {
				primeArr[i] = BigInteger.probablePrime(bitLength, random);
				unique = true;
				for(int j = 0; j < i; j++) {
					if(primeArr[i] == primeArr[j]) {
						unique = false;
						break;
					}
				}
			}
			while(!unique);
		}
		
		return primeArr;
	}

	private class MyThread extends Thread {
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

}