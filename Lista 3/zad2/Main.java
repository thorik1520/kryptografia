package kryptografia_z2_3;

import java.math.BigInteger;
import java.security.SecureRandom;

public class Main {	
	public static void main (String args[]) throws InterruptedException {
		
		SecureRandom random;
		BigInteger[] primeArr;
		MyThread[] threadArr;
		int primesCount, bitLength;
		
		if(args.length == 2) {
			primesCount = Integer.parseInt(args[0]);
			bitLength = Integer.parseInt(args[1]);
		}
		else {
			primesCount = 5;
			bitLength = 1000;
		}
		
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
			System.out.println(primeArr[i]);
		}
		
/*
			do {
				primesArr[i] = BigInteger.probablePrime(bitLength, random);
				unique = true;
				for(int j = 0; j < i; j++) {
					if(primesArr[i] == primesArr[j]) {
						unique = false;
						break;
					}
				}
			}
			while(!unique);
*/
	}
}

