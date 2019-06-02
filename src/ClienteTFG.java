
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONArray;
import org.json.JSONObject;

public class ClienteTFG implements Runnable {
    
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private RSAPublicKeySpec publicKeySpec;
    
    private SecretKey claveSimetricaSecreta;
    private SecureRandom secureRandom;
    private byte[] claveSimetrica;
    private String respuestaEnc;
    
    private GCMParameterSpec parameterSpec;
    
    private PublicKey serverPublicKey;
    private Cipher cifradorAsimetrico;
    private Cipher cifradorSimetrico;
    
    private ObjectOutputStream salida;
    private ObjectInputStream entrada;
    private Socket servidor;
    
    private JSONObject pregunta;
    private JSONObject respuesta;
	private JSONArray content;
	
	private String userName = "";
	private String passWord = "";
	private String token;    
	private final Thread conexion;
	
	private static ClienteTFG cliente;
	
	private ClienteTFG(String userName, String passWord) {
		this.userName = userName;
		this.passWord = passWord;
		conexion = new Thread(this, "nombreDelHilo");
	}
	
	public static void iniciarConexion(String userName, String passWord) {
		cliente = new ClienteTFG(userName,passWord);
		cliente.conexion.start();	
	}
	
	public static ClienteTFG getCliente() {
		return cliente;
	}

	@Override
	public void run() {
		
		if (userName.equals("") || passWord.equals("")) {
			System.out.println("No pueden quedar campos vac�os!");
			return;
		}

        try {
            
        	/*
        	 * Inicializa las claves de cifrado asim�trico y abre una conexi�n con el servidor 
        	 */
        	
            secureRandom = new SecureRandom();
            initializeKey();
            servidor = new Socket("proyectobap.ddns.net",35698);
            salida = new ObjectOutputStream(servidor.getOutputStream());
            entrada = new ObjectInputStream(servidor.getInputStream());
            
        } catch (Exception e) {
        	System.out.println(e.getMessage());
        }
        
        try {
        	
        	/*
        	 * Intercambia las claves con el servidor y hace una prueba de conexi�n para
        	 * comprobar la validez de las claves
        	 */
            
            intercambioClaves();
            cifradorAsimetrico = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cifradorSimetrico = Cipher.getInstance("AES/GCM/NoPadding");
            
            String check = asymetricDecript((String) entrada.readObject());
            enviar(asymetricEncrypt(check));
            
            if (entrada.readInt() == 206) {
                System.out.println("Comunicaci�n OK");
                System.out.print("Recibiendo clave simetrica... ");
                String claveVolatil = (String)entrada.readObject();
                claveSimetrica = Base64.getDecoder().decode(claveVolatil.getBytes());
                inicializacionClaveSimetrica();
                System.out.println("OK");
            } else {
                System.err.println("Comunicaci�n fall�");
                System.exit(0);
            }
            
            /*
             * Env�a al servidor las credenciales para obtener un token de conexi�n 
             * si fuesen validas
             */
            
            enviar(symetricEncrypt(userName+","+passWord));
            
            respuestaEnc = (String) entrada.readObject();
            respuesta = new JSONObject(symetricDecript(respuestaEnc));
            content = new JSONArray();
            
            /*
             * Si las credenciales son v�lidas, guarda el token facilitado por el servidor
             * y continua
             */
            
            if (respuesta.getInt("response") == 200) {
            	content = respuesta.getJSONArray("content");
            	token = content.getJSONObject(0).getString("content");
            } else {
            	System.err.println("Login incorrecto");
            	this.cerrarConexion();
            }
            
            

        } catch (UnknownHostException e) {
            // Controlar
        } catch (IOException e) {
            // Controlar
        } catch (ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException ex) {
            // Controlar
        } catch (Exception ex) {
            // Controlar
        }
        
    }
	
	public void cerrarConexion() throws Exception {
		entrada.close();
        salida.close();
        servidor.close();
	}
	
	public JSONObject peticion(JSONObject peticion) throws Exception {
		
		enviar(symetricEncrypt(peticion.toString()));
        
        if (pregunta.getString("peticion").equalsIgnoreCase("exit")) {
            System.out.println("Desconectando...");
            this.cerrarConexion();
            System.exit(0);
        }
        
        respuestaEnc = (String) entrada.readObject();
        return new JSONObject(symetricDecript(respuestaEnc));
        
        
        /*System.out.println(respuesta.getInt("response"));
        
        content = new JSONArray();
        content = respuesta.getJSONArray("content");
        
        for (int i = 0; i < content.length(); i++) {
        	System.out.println(content.getJSONObject(i).toString());
        }*/
		
	}
	
/******************************************************************************/        
    
    private void inicializacionClaveSimetrica() {
        claveSimetricaSecreta = new SecretKeySpec(claveSimetrica, "AES");
    }
    
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

    private void intercambioClaves() throws 
            InvalidKeySpecException, 
            NoSuchAlgorithmException, 
            IOException, 
            ClassNotFoundException {
        
        System.out.print("Enviando clave publica propia... ");
        salida.writeObject(publicKeySpec.getModulus());
        salida.flush();
        salida.writeObject(publicKeySpec.getPublicExponent());
        salida.flush();
        System.out.println("OK");
        
        System.out.print("Recibiendo clave publica del servidor... ");
        BigInteger modulo = (BigInteger) entrada.readObject();
        BigInteger exponente = (BigInteger) entrada.readObject();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        serverPublicKey = keyFactory.generatePublic(new RSAPublicKeySpec(modulo,exponente));
        System.out.println("OK");
    }
    
/******************************************************************************/
	
    private String symetricEncrypt(String mensaje) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException { 
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
    
    private String symetricDecript(String mensajeCifrado64) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException { 
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
    
    private String asymetricEncrypt(String mensaje) throws 
            UnsupportedEncodingException, 
            IllegalBlockSizeException, 
            BadPaddingException, 
            InvalidKeyException {
        
        cifradorAsimetrico.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        byte[] mensajeCifrado = cifradorAsimetrico.doFinal(mensaje.getBytes("UTF8"));
        return new String(Base64.getEncoder().encode(mensajeCifrado));
    }
    
/******************************************************************************/
    
    private String asymetricDecript(String mensajeCifrado64) throws 
            IllegalBlockSizeException, 
            BadPaddingException, 
            InvalidKeyException {
        
        byte[] mensajeCifrado = Base64.getDecoder().decode(mensajeCifrado64);
        cifradorAsimetrico.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cifradorAsimetrico.doFinal(mensajeCifrado));
    }
    
/******************************************************************************/    
    
    private void enviar(Object mensaje) throws IOException {
        salida.writeObject(mensaje);
        salida.flush();
    }
    
/******************************************************************************/

    public String getToken() {
    	return token;
    }
    
}
