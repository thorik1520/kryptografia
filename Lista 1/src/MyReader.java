package kryptografia_z1_l1;

import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

class MyReader {
	
	protected static List<List<Integer>> readCryptograms(String fileName) throws Exception{
		FileReader fr = new FileReader(fileName);
		List<List<Integer>> kryptogramy = new ArrayList<>();
		List<Integer> kryptogram = new ArrayList<>();
		int c;
		boolean readingBits = false;
		char[] readBits = new char[8];
		while((c = fr.read()) != -1) {
			if(c != 48 && c != 49) {
				if(readingBits == true) {
					kryptogramy.add(kryptogram);
					readingBits = false;
				}
				continue;
			}
			else {
				if(readingBits == false) {
					kryptogram = new ArrayList<>();
					readingBits = true;
				}
				
				readBits[0] = (char)c;	// Już pobrany pierwszy bit
				fr.read(readBits,1,7);	// + kolejne 7 do pełnych 8
				fr.read(); 				// + spacja by przejść dalej
				kryptogram.add(Integer.parseInt(new String(readBits),2));
			}			
		}
		fr.close();
		return kryptogramy;
	}
	
	protected static List<Integer> readMessage(String fileName) throws Exception {
		FileReader fr = new FileReader(fileName);
		List<Integer> message = new ArrayList<>();
		int c;
		char[] readBits = new char[8];
		while((c = fr.read()) != -1) {
			readBits[0] = (char)c;	// Już przeczytany bit znaku	
			fr.read(readBits,1,7);	// + kolejne 7 do pełnych 8
			fr.read(); 				// + spacja by przejść do kolejnego
			message.add(Integer.parseInt(new String(readBits),2));	
		}
		fr.close();
		return message;
	}
}
