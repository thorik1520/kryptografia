package kryptografia_z1_l3;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.SecureRandom;

public class Main {
	
	private static BigInteger n, e, euler, d;
	private static final BigInteger one = new BigInteger("1");
	private static final BigInteger two = new BigInteger("2");
	
	// Wydruk do plików
	static void printFile(String filename, String text) throws Exception {
		PrintWriter writer = new PrintWriter(filename, "UTF-8");
		writer.println(text);
		writer.close();
	}
	
	// Generowanie kluczy i zapis do plików 'private_key' i 'public_key'
	private static void genKeys(int k, int b) throws Exception {
		int primesCount = k;
		int bitLength = b;
		
		// Szukanie liczb pierwszych
		PrimeFinder primeFinder = new PrimeFinder();
		BigInteger[] primes = primeFinder.getUniquePrimes(primesCount, bitLength);
		
		// n = 1 * p1 * ... * pk
		n = one;
		for(int i = 0; i < primesCount; i++)
			n = n.multiply(primes[i]);
		
		// euler = 1 * (p1 - 1) * ... * (pk - 1)
		euler = one;
		for(int i = 0; i < primesCount; i++)
			euler = euler.multiply(primes[i].subtract(one));
		
		// e - losowa liczba
		SecureRandom random = new SecureRandom();
		do {
			e = new BigInteger(bitLength - 1, random); // e < euler
			e = e.add(new BigInteger("2")); // e > 1
		}
		while(!euler.gcd(e).equals(one)); // gcd(e, euler) = 1
		
		// d = e^-1 % euler
		d = e.modInverse(euler);
		
		// Zapis do plików
		printFile("private_key",d.toString());
		printFile("public_key",n.toString() + "\n" + e.toString());
	}
	
	private static void readKeys() throws Exception {
		BufferedReader br; 
		
		br = new BufferedReader(new FileReader("private_key"));
		d = new BigInteger(br.readLine());
		br.close();
		
		br = new BufferedReader(new FileReader("public_key"));
		n = new BigInteger(br.readLine());
		e = new BigInteger(br.readLine());
		br.close();
	}
	
	private static BigInteger power(BigInteger base, BigInteger exponent) {
		if(exponent.equals(one))
			return base;
		else if( (exponent.mod(two).equals(BigInteger.ZERO)) )
			return power(base.pow(2),exponent.divide(two));
		else
			return base.multiply(power(base.pow(2), exponent.subtract(one).divide(two)));
	}
	
	// Szyfruje i zapisuje do pliku 'cipher'
	private static void enc(String message) throws Exception {
		BigInteger data = new BigInteger(message);
		
		BigInteger cipher = power(data, e).mod(n);
		printFile("cipher", cipher.toString());
		System.out.println(cipher.toString());
	}
	
	// Deszyfruje i zapisuje do pliku 'plain'
	private static void dec(String cipher) throws Exception {
		BigInteger data = new BigInteger(cipher);
		BigInteger plain = power(data, d).mod(n);
		printFile("plain", plain.toString());
		System.out.println(plain.toString());
	}
	
	public static void main(String[] args) throws Exception {
		if(args.length < 1)
			return;
		
		if(args[0].equals("gen")) {
			if(args.length == 3)
				genKeys(new Integer(args[1]),new Integer(args[2]));
			else
				genKeys(2,8);
		}
		else if(args[0].equals("enc")) {
			readKeys();
			if(args.length == 2)
				enc(args[1]);
			else
				enc("123");
		}
		else if(args[0].equals("dec")) {
			readKeys();
			if(args.length == 2)
				dec(args[1]);
			else
				return;
		}

	}

}
