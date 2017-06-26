package org.warp.elevencrypt;

import java.awt.GraphicsEnvironment;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Random;

import javax.swing.JOptionPane;

import org.warp.gui.ModernDialog;
import org.warp.gui.ModernDialog.ModernExtensionFilter;

/**
 * Hello world!
 *
 */
public class App 
{
	private static final int BYTES_COUNT = 0x100;
	private static long[][] byteIndexList = new long[BYTES_COUNT][0x8000];
	private static int[] byteIndexListSize = new int[BYTES_COUNT];
	private static Random random = new Random();
	private static HashMap<Long, Byte> decryptionCache = new HashMap<Long,Byte>();
	
    public App(String[] args) throws IOException {
    	long time = System.currentTimeMillis();
    	
    	if (args[0].equals("DECRYPT")) {
    		decrypt(args);
        	System.out.println("Decrypted!");
    	} else {
    		encrypt(args);
        	System.out.println("Encrypted!");
    	}
    	
    	System.out.println("Seconds elapsed: "+(((double)(System.currentTimeMillis()-time))/1000d));
	}

	public static void main( String[] args ) throws IOException
    {
    	if(args.length != 4) {
    		System.err.println("java -jar elevencrypt.jar ENCRYPT \"<INPUT_FILE>\" \"<KEY_FILE>\" \"<OUTPUT_FILE>\"");
    		System.err.println("java -jar elevencrypt.jar DECRYPT \"<ENCRTPYED_FILE>\" \"<KEY_FILE>\" \"<OUTPUT_FILE>\"");
    		
    		gui();
    	} else {
    		new App(args);
    	}
    }
    
    private static void gui() {

		if (!GraphicsEnvironment.isHeadless()) {
			final String[] buttons = { "Encrypt", "Decrypt", "Cancel"};    
			int returnValue = JOptionPane.showOptionDialog(null, "Choose an option:", "ElevenCrypt",
			        JOptionPane.WARNING_MESSAGE, 0, null, buttons, buttons[2]);
			
			if (returnValue == 0 || returnValue == 1) {
    			final String[] newArgs = new String[4];
    			newArgs[0] = returnValue==0?"ENCRYPT":"DECRYPT";
    			ModernDialog.runLater(() -> {
    				ModernDialog fc = new ModernDialog();
        			if (returnValue == 0) {
            			fc.setTitle("Choose a file to encrypt...");
        			} else {
            			fc.setTitle("Choose a file to decrypt...");
        			}
        			File tmp = fc.show(null);
        			File original;
        			if (tmp instanceof File) {
        				original = tmp;
        				newArgs[1] = tmp.toString();
        				fc = new ModernDialog();
        				fc.setTitle("Choose a file to use as a key...");
        				tmp = fc.show(null);
        				if (tmp instanceof File) {
        					newArgs[2] = tmp.toString();
            				fc = new ModernDialog();
            				fc.setTitle("Save the output...");
            				fc.setExtensions(new ModernExtensionFilter(getFileExtension(original).toUpperCase()+" files",  "*."+getFileExtension(original)), new ModernExtensionFilter("All files", "*.*"));
            				tmp = fc.showSaveDialog(null);
            				if (tmp instanceof File) {
            					newArgs[3] = tmp.toString();
                				try {
									new App(newArgs);
								} catch (IOException e) {
									e.printStackTrace();
									System.exit(1);
								}
            				}
        				}
        			}
        			
        			gui();
                	System.exit(0);
    			});
			} else {
				System.exit(0);
			}
		}
	}

	private static void decrypt(String[] args) throws IOException {
    	Path fileOutput = Paths.get(args[1]);
    	Path fileKey = Paths.get(args[2]);
    	Path file = Paths.get(args[3]);

    	long fileKeySize = fileKey.toFile().length();
    	long maxIndex = fileKeySize+BYTES_COUNT-1;

    	FileInputStream r = new FileInputStream(fileOutput.toFile());
    	RandomAccessFile key = new RandomAccessFile(fileKey.toFile(), "r");
    	FileOutputStream w = new FileOutputStream(file.toFile());
    	final byte[] byteLengthBytes = new byte[Integer.BYTES];
    	if (r.read(byteLengthBytes)!=Integer.BYTES) {
        	w.close();
        	r.close();
        	key.close();
    		throw new IOException("This file is empty!");
    	}
    	final int byteLength = bytesToInt(byteLengthBytes);
    	System.out.println("Byte length: " + byteLength);
    	byte[] longsBuf = new byte[2048*byteLength];
    	byte[] decryptedBytes = new byte[2048];
    	while(r.available() > 0) {
    		int longsBufSize = r.read(longsBuf);
    		for (int i = 0; i < longsBufSize; i+=byteLength) {
        		long index = bytesToLong(expandByteArray(Arrays.copyOfRange(longsBuf, i, i+byteLength), Long.BYTES));
        		if (index >= fileKeySize) {
            		if (index > maxIndex) {
            	    	w.close();
            	    	r.close();
            	    	key.close();
            			throw new IOException("index > file key size");
            		}
            		decryptedBytes[i/byteLength] = (byte)(index-fileKeySize);
        		} else {
        			if (decryptionCache.containsKey(index)) {
        				decryptedBytes[i/byteLength] = decryptionCache.get(index);
        			} else {
	        			key.seek(index);
	        			byte decrB = (byte) key.read();
	        			decryptionCache.put(index, decrB);
	        			decryptedBytes[i/byteLength] = decrB;
        			}
        		}
    		}
    		
    		w.write(Arrays.copyOf(decryptedBytes, longsBufSize/byteLength));
    	}
    	w.close();
    	r.close();
    	key.close();
	}

	private static void encrypt(String[] args) throws IOException {
    	Path file = Paths.get(args[1]);
    	Path fileKey = Paths.get(args[2]);
    	Path fileOutput = Paths.get(args[3]);

    	long fileKeySize = fileKey.toFile().length();
    	
    	//Fill bytes with indices of key file
    	FileInputStream r = new FileInputStream(fileKey.toFile());
    	long index = 0;
    	byte[] valBuffer = new byte[2048];
    	while(r.available() > 0) {
    		int valBufferSize = r.read(valBuffer);
    		for(int i = 0; i < valBufferSize; i++) {
    			int val = valBuffer[i] & 0xFF;
        		if (byteIndexListSize[val] < byteIndexList[val].length) {
        			byteIndexList[val][byteIndexListSize[val]] = index;
        			byteIndexListSize[val]++;
        		} else {
        			byteIndexList[val][(int)(random.nextInt(byteIndexList[val].length))] = index;
        		}
        		index++;
    		}
    	}
    	r.close();
    	
    	//Fix empty bytes
    	for(int val = 0; val < byteIndexListSize.length; val++) {
    		if (byteIndexListSize[val] == 0) {
    			byteIndexList[val][0] = fileKeySize+val;
    			byteIndexListSize[val]++;
    			index++;
    		}
    	}
    	
    	r = new FileInputStream(file.toFile());
    	FileOutputStream w = new FileOutputStream(fileOutput.toFile());
    	valBuffer = new byte[2048];
    	final int byteLength = byteLength(index);
    	w.write(intToBytes(byteLength));
    	System.out.println("Byte length: "+byteLength);
    	while(r.available() > 0) {
    		int valBufferSize = r.read(valBuffer);
	    	byte[] encBuffer = new byte[valBufferSize*byteLength];
    		for(int i = 0; i < valBufferSize; i++) {
    			int val = valBuffer[i] & 0xFF;
    	    	System.arraycopy(reduceByteArray(longToBytes(byteIndexList[val][((int)(random.nextInt(byteIndexListSize[val])))]), byteLength), 0, encBuffer, i*byteLength, byteLength);
    		}
    		w.write(encBuffer);
    	}
    	r.close();
    	w.close();
	}
	
	private static String getFileExtension(File file) {
	    String name = file.getName();
	    try {
	        return name.substring(name.lastIndexOf(".") + 1);
	    } catch (Exception e) {
	        return "";
	    }
	}
	
	private static byte[] reduceByteArray(byte[] bytes, int len) {
		return Arrays.copyOfRange(bytes, bytes.length-len, bytes.length);
	}
	
	
	private static byte[] expandByteArray(byte[] bytes, int len) {
		byte[] orig = new byte[len];
		System.arraycopy(bytes, 0, orig, len-bytes.length, bytes.length);
		return orig;
	}

	private static int bitLength(long number) {
		int len = 63;
		long mask;
		do {
    		len--;
			mask = 0x1L << len;
    		if ((number & mask) == mask) {
    			return len;
    		}
		} while (mask > 0);
		return 0;
	}
	
	private static int byteLength(long number) {
		int bitLen = bitLength(number);
		return (int) Math.ceil(((double)bitLen)/8d);
	}

	public static byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(x);
        return buffer.array();
    }

    public static long bytesToLong(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.put(bytes);
        buffer.flip();//need flip 
        return buffer.getLong();
    }

	public static byte[] intToBytes(int x) {
        ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
        buffer.putInt(x);
        return buffer.array();
    }

    public static int bytesToInt(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
        buffer.put(bytes);
        buffer.flip();//need flip 
        return buffer.getInt();
    }
}
