import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptModule {
	
	private PublicKey publicKey;
    private PrivateKey privateKey;
    private RSAPublicKeySpec publicKeySpec;
    
    private SecretKey claveSimetricaSecreta;
    private SecureRandom secureRandom;
    private byte[] claveSimetrica;
    
    private GCMParameterSpec parameterSpec;
    
    private PublicKey serverPublicKey;
    private Cipher cifradorAsimetrico;
    private Cipher cifradorSimetrico;
	
	
	/******************************************************************************/
	
	public void initializeKey() throws Exception {
		
		System.out.print("Iniciando generador de claves... ");
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(1024);
		System.out.println("OK");
		    
		    System.out.print("Generando par de claves... ");
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		System.out.println("OK");
			
		publicKey = keyPair.getPublic();
		privateKey = keyPair.getPrivate();
			
		    System.out.print("Generando clave publica exportable... ");
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		publicKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
		System.out.println("OK");
		
    }
	
	/******************************************************************************/
	
	public void inicializacionClaveSimetrica() {
        claveSimetricaSecreta = new SecretKeySpec(claveSimetrica, "AES");
    }
	
	/******************************************************************************/    
	
    public String symetricEncrypt(String mensaje) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException { 
    	
    	byte[] iv = new byte[12];
    	secureRandom.nextBytes(iv);
    	parameterSpec = new GCMParameterSpec(128, iv);
        cifradorSimetrico.init(Cipher.ENCRYPT_MODE, claveSimetricaSecreta, parameterSpec);
        
        byte[] cipherText = cifradorSimetrico.doFinal(mensaje.getBytes());
        ByteBuffer bf = ByteBuffer.allocate(4+iv.length+cipherText.length); 
		bf.putInt(iv.length);
		bf.put(iv);
		bf.put(cipherText);
        
        byte[] cipherMessage = bf.array();
        return new String(Base64.getEncoder().encode(cipherMessage));
        
    }
    
    /******************************************************************************/
    
    public String symetricDecript(String mensajeCifrado64) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException { 
    	
    	byte[] cifMen = Base64.getDecoder().decode(mensajeCifrado64);
        ByteBuffer bf = ByteBuffer.wrap(cifMen);
        int ivLength = bf.getInt();
        if (ivLength < 12 || ivLength >=16) {
                throw new IllegalArgumentException("invalid iv length");
        }
        byte[] iv = new byte[ivLength];
        bf.get(iv);
        byte[] cipherText = new byte[bf.remaining()];
        bf.get(cipherText);
        
        parameterSpec = new GCMParameterSpec(128, iv);
        cifradorSimetrico.init(Cipher.DECRYPT_MODE, claveSimetricaSecreta, parameterSpec);
        return new String(cifradorSimetrico.doFinal(cipherText));
        
    }
    
    /******************************************************************************/
    
    public String asymetricEncrypt(String mensaje) throws 
            UnsupportedEncodingException, 
            IllegalBlockSizeException, 
            BadPaddingException, 
            InvalidKeyException {
        
        cifradorAsimetrico.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        byte[] mensajeCifrado = cifradorAsimetrico.doFinal(mensaje.getBytes("UTF8"));
        return new String(Base64.getEncoder().encode(mensajeCifrado));
	        
    }
    
    /******************************************************************************/
    
    public String asymetricDecript(String mensajeCifrado64) throws 
            IllegalBlockSizeException, 
            BadPaddingException, 
            InvalidKeyException {
        
        byte[] mensajeCifrado = Base64.getDecoder().decode(mensajeCifrado64);
        cifradorAsimetrico.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cifradorAsimetrico.doFinal(mensajeCifrado));
    }
	
    /******************************************************************************/
    /**************************** GETTERS *****************************************/
    /******************************************************************************/
    
    public PublicKey getPublicKey() {
		return publicKey;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public RSAPublicKeySpec getPublicKeySpec() {
		return publicKeySpec;
	}

	public SecretKey getClaveSimetricaSecreta() {
		return claveSimetricaSecreta;
	}

	public SecureRandom getSecureRandom() {
		return secureRandom;
	}

	public byte[] getClaveSimetrica() {
		return claveSimetrica;
	}

	public GCMParameterSpec getParameterSpec() {
		return parameterSpec;
	}

	public PublicKey getServerPublicKey() {
		return serverPublicKey;
	}

	public Cipher getCifradorAsimetrico() {
		return cifradorAsimetrico;
	}

	public Cipher getCifradorSimetrico() {
		return cifradorSimetrico;
	}
	
	/******************************************************************************/
    /**************************** SETTERS *****************************************/
    /******************************************************************************/

	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}

	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public void setPublicKeySpec(RSAPublicKeySpec publicKeySpec) {
		this.publicKeySpec = publicKeySpec;
	}

	public void setClaveSimetricaSecreta(SecretKey claveSimetricaSecreta) {
		this.claveSimetricaSecreta = claveSimetricaSecreta;
	}

	public void setSecureRandom(SecureRandom secureRandom) {
		this.secureRandom = secureRandom;
	}

	public void setClaveSimetrica(byte[] claveSimetrica) {
		this.claveSimetrica = claveSimetrica;
	}

	public void setParameterSpec(GCMParameterSpec parameterSpec) {
		this.parameterSpec = parameterSpec;
	}

	public void setServerPublicKey(PublicKey serverPublicKey) {
		this.serverPublicKey = serverPublicKey;
	}

	public void setCifradorAsimetrico(Cipher cifradorAsimetrico) {
		this.cifradorAsimetrico = cifradorAsimetrico;
	}

	public void setCifradorSimetrico(Cipher cifradorSimetrico) {
		this.cifradorSimetrico = cifradorSimetrico;
	}

}
