package kryptografia_z1_l1;

import java.util.List;

public class Main {

	private static final int printable_start = 32;
	private static final int printable_end = 125;
	
	public static void main(String[] args) throws Exception {
		List<List<Integer>> cryptograms = MyReader.readCryptograms(args[0]);
		List<Integer> message = MyReader.readMessage(args[1]);
		
		int xor[][] = new int[message.size()][];
		for(int i = 0; i < message.size(); i++)
			xor[i] = new int[cryptograms.size()];
		
		for(int i = 0; i < message.size(); i++) {
			for(int j = 0; j < cryptograms.size(); j++)
				xor[i][j] = message.get(i) ^ cryptograms.get(j).get(i);
		}
		
		int[] suspects = new int[message.size()];
		int count, max, x;
		for(int i = 0; i < message.size(); i++) {
			max = 0;
			for(int j = printable_start; j <= printable_end; j++) {
				count = 0;
				for(int k = 0; k < cryptograms.size(); k++) {
					x = xor[i][k] ^ (int)j;
					if(Character.isLetter(x) || (char)x == ' ')
						count++;
				}
				if(count > max) {
					max = count;
					suspects[i] = j;
				}
			}
		}

		for(int i : suspects)
			System.out.print((char)i);
		System.out.print('\n');
	}
}