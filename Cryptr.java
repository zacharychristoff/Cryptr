/*
 *               Cryptr
 *
 * Cryptr is a java encryption toolset
 * that can be used to encrypt/decrypt files
 * and keys locally, allowing for files to be
 * shared securely over the world wide web
 *
 * Cryptr provides the following functions:
 *	 1. Generating a secret key
 *   2. Encrypting a file with a secret key
 *   3. Decrypting a file with a secret key
 *   4. Encrypting a secret key with a public key
 *   5. Decrypting a secret key with a private key
 *
 */

import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;


public class Cryptr {

	
	/**
	 * Generates an 128-bit AES secret key and writes it to a file
	 *
	 * @param  secKeyFile    name of file to store secret key
	 */
	static void generateKey(String secKeyFile) throws Exception{
		//Generate secret key
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		SecretKey secretKey = keyGen.generateKey();
		
		//Write to binary file
		try (FileOutputStream output = new FileOutputStream(secKeyFile)) {
		    byte[] keyB = secretKey.getEncoded();
		    output.write(keyB);
		}
	}

	

	/**
	 * Extracts secret key from a file, generates an
	 * initialization vector, uses them to encrypt the original
	 * file, and writes an encrypted file containing the initialization
	 * vector followed by the encrypted file data
	 *
	 * @param  originalFile    name of file to encrypt
	 * @param  secKeyFile      name of file storing secret key
	 * @param  encryptedFile   name of file to write iv and encrypted file data
	 * @throws Exception 
	 */
	static void encryptFile(String originalFile, String secKeyFile, String encryptedFile) throws Exception {
		//Extracts secret key from file
		byte[] keyB = Files.readAllBytes(Paths.get(secKeyFile));
		SecretKeySpec secretKey = new SecretKeySpec(keyB, "AES");
		
		
		//Generates an initialization vector
		SecureRandom random = new SecureRandom();
		byte[] iv = new byte[128/8];
		random.nextBytes(iv);
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		
		
		//Create cipher
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
		
		
		//Write initialization vector to encrypted file & Encrypt file
		try (FileInputStream input = new FileInputStream(originalFile);
	             FileOutputStream output = new FileOutputStream(encryptedFile)){
			output.write(iv);
			processFile(cipher, input, output);
			output.close();
		}
	}
	

	
	/**
	 * Extracts the secret key from a file, extracts the initialization vector
	 * from the beginning of the encrypted file, uses both secret key and
	 * initialization vector to decrypt the encrypted file data, and writes it to
	 * an output file
	 *
	 * @param  encryptedFile    name of file storing iv and encrypted data
	 * @param  secKeyFile	    name of file storing secret key
	 * @param  outputFile       name of file to write decrypted data to
	 * @throws Exception 
	 */
	static void decryptFile(String encryptedFile, String secKeyFile, String outputFile) throws Exception {	
		//Extracts initialization vector from file
		FileInputStream input = new FileInputStream(encryptedFile);
		byte[] iv = new byte[128/8];
		input.read(iv);
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		
		
		//Extracts secret key
		byte[] keyB = Files.readAllBytes(Paths.get(secKeyFile));
		SecretKeySpec secretKey = new SecretKeySpec(keyB, "AES");

		
		//Decrypts the file
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);	
	    try(FileOutputStream output = new FileOutputStream(outputFile)){
			processFile(cipher, input, output);
	    }
	}

	

	/**
	 * Extracts secret key from a file, encrypts a secret key file using
     * a public Key (*.der) and writes the encrypted secret key to a file
	 *
	 * @param  secKeyFile    name of file holding secret key
	 * @param  pubKeyFile    name of public key file for encryption
	 * @param  encKeyFile    name of file to write encrypted secret key
	 * @throws Exception 
	 */
	static void encryptKey(String secKeyFile, String pubKeyFile, String encKeyFile) throws Exception {
		//Extract Public Key from file
		byte[] bytes = Files.readAllBytes(Paths.get(pubKeyFile));
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);
		KeyFactory keyFact = KeyFactory.getInstance("RSA");
		PublicKey pub = keyFact.generatePublic(keySpec);
		
		
		//Extract Secret Key from file
		byte [] keyB = Files.readAllBytes(Paths.get(secKeyFile));
		SecretKeySpec secretKey = new SecretKeySpec(keyB, "AES");
		
		
		//Encrypt Secret Key with Public Key
		FileOutputStream output = new FileOutputStream(encKeyFile);
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, pub);
		byte[] b = cipher.doFinal(secretKey.getEncoded());
		output.write(b);
	}


	
	/**
	 * Decrypts an encrypted secret key file using a private Key (*.der)
	 * and writes the decrypted secret key to a file
	 *
	 * @param  encKeyFile       name of file storing encrypted secret key
	 * @param  privKeyFile      name of private key file for decryption
	 * @param  secKeyFile       name of file to write decrypted secret key
	 * @throws Exception 
	 */
	static void decryptKey(String encKeyFile, String privKeyFile, String secKeyFile) throws Exception {
		//Extract private key from file
		byte[] bytes = Files.readAllBytes(Paths.get(privKeyFile));
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
		KeyFactory keyFact = KeyFactory.getInstance("RSA");
		PrivateKey priv = keyFact.generatePrivate(keySpec);
		
		
		//Extract encrypted secret key from file & decrypt w/ private key
		FileInputStream input = new FileInputStream(encKeyFile);
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, priv);
		byte[] b = new byte[256];
		input.read(b);
		byte[] keyB = cipher.doFinal(b);
		SecretKeySpec secretKey = new SecretKeySpec(keyB, "AES");

		
		//Write to secKeyFile
		try (FileOutputStream output = new FileOutputStream(secKeyFile)) {
		    byte[] keyB_s = secretKey.getEncoded();
		    output.write(keyB_s);
		}
	}

	
	
	//Helper to process the file
	static private void processFile(Cipher cipher, InputStream input, OutputStream output)
		    throws javax.crypto.IllegalBlockSizeException,
		           javax.crypto.BadPaddingException,
		           java.io.IOException
		{
		    byte[] inputBuf = new byte[1024];
		    int len;
		    while ((len = input.read(inputBuf)) != -1) {
		        byte[] outputBuf = cipher.update(inputBuf, 0, len);
		        if ( outputBuf != null ) output.write(outputBuf);
		    }
		    byte[] outputBuf = cipher.doFinal();
		    if ( outputBuf != null ) output.write(outputBuf);
		}
	

	
	/**
	 * Main Program Runner
	 */
	
	
	public static void main(String[] args) throws Exception{

		String func;

		if(args.length < 1) {
			func = "";
		} else {
			func = args[0];
		}

		switch(func)
		{
			case "generatekey":
				if(args.length != 2) {
					System.out.println("Invalid Arguments.");
					System.out.println("Usage: Cryptr generatekey <key output file>");
					break;
				}
				System.out.println("Generating secret key and writing it to " + args[1]);
				generateKey(args[1]);
				break;
			case "encryptfile":
				if(args.length != 4) {
					System.out.println("Invalid Arguments.");
					System.out.println("Usage: Cryptr encryptfile <file to encrypt> <secret key file> <encrypted output file>");
					break;
				}
				System.out.println("Encrypting " + args[1] + " with key " + args[2] + " to "  + args[3]);
				encryptFile(args[1], args[2], args[3]);
				break;
			case "decryptfile":
				if(args.length != 4) {
					System.out.println("Invalid Arguments.");
					System.out.println("Usage: Cryptr decryptfile <file to decrypt> <secret key file> <decrypted output file>");
					break;
				}
				System.out.println("Decrypting " + args[1] + " with key " + args[2] + " to " + args[3]);
				decryptFile(args[1], args[2], args[3]);
				break;
			case "encryptkey":
				if(args.length != 4) {
					System.out.println("Invalid Arguments.");
					System.out.println("Usage: Cryptr encryptkey <key to encrypt> <public key to encrypt with> <encrypted key file>");
					break;
				}
				System.out.println("Encrypting key file " + args[1] + " with public key file " + args[2] + " to " + args[3]);
				encryptKey(args[1], args[2], args[3]);
				break;
			case "decryptkey":
				if(args.length != 4) {
					System.out.println("Invalid Arguments.");
					System.out.println("Usage: Cryptr decryptkey <key to decrypt> <private key to decrypt with> <decrypted key file>");
					break;
				}
				System.out.println("Decrypting key file " + args[1] + " with private key file " + args[2] + " to " + args[3]);
				decryptKey(args[1], args[2], args[3]);
				break;
			default:
				System.out.println("Invalid Arguments.");
				System.out.println("Usage:");
				System.out.println("  Cryptr generatekey <key output file>");
				System.out.println("  Cryptr encryptfile <file to encrypt> <secret key file> <encrypted output file>");
				System.out.println("  Cryptr decryptfile <file to decrypt> <secret key file> <decrypted output file>");
				System.out.println("  Cryptr encryptkey <key to encrypt> <public key to encrypt with> <encrypted key file> ");
				System.out.println("  Cryptr decryptkey <key to decrypt> <private key to decrypt with> <decrypted key file>");
		}

		System.exit(0);

	}

}