package src;

import java.io.*;
import java.util.*;
import java.math.*;

/*
 * @author Sasha Demyanik
 * CS427 Program 2
 * 
 */

public class Cryptosystem {

	protected final int blockSize = 32;
	protected BigInteger zero = new BigInteger("0");
	protected BigInteger one = new BigInteger("1");
	protected BigInteger two = new BigInteger("2");
	protected String pubkey = "src/pubkey.txt";
	protected String prikey = "src/prikey.txt";
	protected String plaintext = "src/ptext.txt";
	protected String ciphertext = "src/ctext.txt";
	protected String decrypttext = "src/dtext.txt";
	
	public Cryptosystem(){
		
	}
	
	/* Returns the binary representation of a string length 8 */
	public String asciiToBin(String a){
		//Using this method from the WSUCrypt project
		byte[] bytes = a.getBytes();
		StringBuilder binary = new StringBuilder();
		for (byte b : bytes){
			int val = b;
			for (int i = 0; i < 8; i++){
				binary.append((val & 128) == 0 ? 0 : 1);
				val <<= 1;
			}
		}
		return binary.toString();
	}
	
	//Convert Binary string to Ascii text
	public String binToAscii(String s){
		ArrayList<String> arr = new ArrayList<String>();
		int count = 0;
		StringBuilder str = new StringBuilder();
		
		for(int i = 0; i < s.length(); i++){
			str.append(s.charAt(i));
			count++;
			if(count%8 == 0){
				int c = Integer.parseInt(str.toString(), 2);
				arr.add((new Character((char) c)).toString());
				str = new StringBuilder();
			}
		}
		
		for(int i = 0; i < arr.size(); i++){
			str.append(arr.get(i));
		}
		
		return str.toString();
	}
	
	//Miller Rabin test!
	boolean isPrime(BigInteger n, Random r) {
		BigInteger s = one;
		BigInteger d = n.subtract(one).divide(two);
		
		if(n.equals(one) || n.equals(zero)) return false;
		
		while( d.mod(two).equals(zero) ){
			d = d.divide(two);
			s = s.add(one);
		}
		
		BigInteger x = new BigInteger(n.bitLength(),r);
		
		if ( powMod(x, d, n) == one){
			return true;
		}
		
		for (int i = 0; i < s.intValue(); i++ ){
			BigInteger x2 = powMod(x, two.pow(i).multiply(d),n );
			if ( x2.equals(n.subtract(one)) || x2.equals(one)){
				return true;
			}
		}
		
		
		return false;
	}

	//Used for a^e mod n
	public BigInteger powMod(BigInteger a, BigInteger e, BigInteger n){
		BigInteger answer = one;
		a = a.mod(n);
		
		while( e.compareTo(zero) == 1 ){
			if ( e.mod(two).equals(one) ){
				answer = (answer.multiply(a)).mod(n);
			}
			e = e.shiftRight(1);
			a = (a.multiply(a)).mod(n);
		}
		return answer;
	}
	
	public void writeToFile(String a, String filename){
		try {
			File newFile = new File(filename);
			if(!newFile.exists()){
				newFile.createNewFile();
			} 
			BufferedWriter newWrite = new BufferedWriter(new FileWriter(newFile));
			newWrite.write(a);
			newWrite.close();
			
		}catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public void key_gen() throws IOException{
		System.out.println("Please enter a random number: ");
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		String input = br.readLine();
		if (input != null){
			long num = Long.parseLong(input);
			Random srand = new Random(num);
			
			BigInteger p = zero;
			BigInteger g = two;
			BigInteger d;
			BigInteger e2;
			BigInteger random;
			
			while( !isPrime(p,srand) ) {
				srand = new Random(num);
				p = new BigInteger(33, 1, srand);
			}
			
			d = new BigInteger(p.bitLength(), srand);
			e2 = powMod(g, d, p);
			
			
			String pub = "" + p.toString() + " " + g + " " + e2;
			String priv = "" + p.toString() + " " + g + " " + d;
			
			writeToFile(pub,pubkey);
			writeToFile(priv,prikey);
		}
	}
	
	public void encryption() throws IOException{
		ArrayList<String> strArr = new ArrayList<String>();
		ArrayList<BigInteger> blocks = new ArrayList<BigInteger>();
		
		File pFile = new File(plaintext);
		if(!pFile.exists()){
			System.out.println("No plaintext file found! Place one in the project src/ folder");
			return;
		}
		BufferedReader pText = new BufferedReader(new FileReader(pFile));
		
		File pubFile = new File(pubkey);
		if(!pubFile.exists()){
			System.out.println("No public keys file! Run the key generation!");
		}
		BufferedReader pub = new BufferedReader(new FileReader(pubFile));
		
		File cFile = new File(ciphertext);
		if(!cFile.exists()){
			cFile.createNewFile();
		} 
		BufferedWriter cText = new BufferedWriter(new FileWriter(cFile));
		
		String[] pub_key = pub.readLine().split(" ");
		
		BigInteger p = new BigInteger(pub_key[0]);
		BigInteger g = new BigInteger(pub_key[1]);
		BigInteger e2 = new BigInteger(pub_key[2]);
		
		StringBuilder s = new StringBuilder();
		String a = pText.readLine();
		while ( a != null ){
			s.append(a + "\n");
			a = pText.readLine();
		}
		String message = asciiToBin(s.toString());
		
		//Going to build 32 bit blocks from the binary string
		s = new StringBuilder();
		int blockCount = 0;
		int maxBlock = 32;
		for (int i = 0; i < message.length(); i++){
			s.append(message.charAt(i));
			blockCount++;
			
			if ( blockCount%maxBlock == 0 || i == message.length()-1 ){
				strArr.add(s.toString());
				s = new StringBuilder();
			}
		}
		
		//Iterate through each 32 bit block and add to blocks array
		for ( int i = 0; i < strArr.size(); i++ ){
			blocks.add(new BigInteger(strArr.get(i), 2));
		}
		
		for ( int i = 0; i < blocks.size(); i++ ){
			BigInteger c1, c2, k, m;
			m = blocks.get(i);
			Random r = new Random();
			k = new BigInteger(p.subtract(one).bitLength(), r);
			c1 = powMod(g, k, p);
			c2 = (powMod(e2, k, p).multiply(m)).mod(p);
			
			cText.write(c1.toString() + "\n" + c2.toString() + "\n");
		}
		
		System.out.println("Finished Encrypting");
		pText.close();
		pub.close(); //Close the pub! It's after midnight!
		cText.close();
	}
	
	public void decryption() throws IOException{
		ArrayList<BigInteger> strArr = new ArrayList<BigInteger>();
		
		File priFile = new File(prikey);
		if ( !priFile.exists() ){
			System.out.println("Error: no private key file found!");
			return;
		}
		BufferedReader priText = new BufferedReader(new FileReader(priFile));
		
		File cFile = new File(ciphertext);
		if ( !cFile.exists() ){
			System.out.println("Error: no ciphertext file found!");
			return;
		}
		BufferedReader cText = new BufferedReader(new FileReader(cFile));
		
		File dFile = new File(decrypttext);
		if(!dFile.exists()){
			dFile.createNewFile();
		} 
		BufferedWriter dText = new BufferedWriter(new FileWriter(dFile));
		
		String[] pri_key = priText.readLine().split(" ");
		BigInteger p = new BigInteger(pri_key[0]);
		BigInteger g = new BigInteger(pri_key[1]);
		BigInteger d = new BigInteger(pri_key[2]);
		
		StringBuilder s = new StringBuilder();
		int bitLen;
		String a = cText.readLine();
		while ( a != null) {
			strArr.add(new BigInteger(a));
			a = cText.readLine();
		}
		
		for ( int i = 0; i < strArr.size(); i+=2 ){
			StringBuilder temp = new StringBuilder();
			BigInteger C1 = powMod(strArr.get(i), p.subtract(one).subtract(d), p);
			BigInteger C2 = strArr.get(i+1);
			BigInteger m = (C1.multiply((C2).mod(p))).mod(p);
			
			//Check if we need to add more zeroes to binary string 
			String mStr = m.toString(2);
			if ( mStr.length() % 32 == 0 ){
				bitLen = 0;
			}else{
				bitLen = 32 - mStr.length()%32;
			}
			for ( int j = 0; j < bitLen; j++ ){
				temp.append("0");
			}
			//Add the actually message and then add to the main message
			temp.append( mStr );
			s.append( temp.toString() );
		}
		
		String d_text = binToAscii( s.toString() );
		dText.write( d_text );
		System.out.println("Finished Decrypting!");
		System.out.println(d_text);
		priText.close();
		cText.close();
		dText.close();
		
	}
	
	public static void main(String[] args) {
		Cryptosystem crypt = new Cryptosystem();
		boolean b = true;
		try{
			BufferedReader br;
			while(b){
				System.out.println("Enter k for key generation, e for encryption, d for decryption or c for close.");
				br = new BufferedReader(new InputStreamReader(System.in));
				String input = br.readLine();
				if(input != null){
					if(input.equals("k")){
						crypt.key_gen();						
						
					} else if (input.equals("e")) {
						System.out.println("Encrypting...");
						crypt.encryption();
					} else if (input.equals("d")) {
						System.out.println("Decrypting...");
						crypt.decryption();
					} else if (input.equals("c")) {
						System.out.println("Program Terminated");
						b = false;
					}
				}
				
				
			}
			
		}catch (Exception e){
			System.err.println("");
		}

	}

}
