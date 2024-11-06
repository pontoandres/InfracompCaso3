import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;

import javax.crypto.KeyGenerator;

public class Simetrico {

    // Constante para el cifrado
    private final static String PADDING = "AES/CBC/PKCS5Padding";
    
    // Método para cifrar con IV del servidor
    public static byte[] cifrar(SecretKey llave, String texto, IvParameterSpec ivSpec) {
        byte[] textoCifrado;
        try {
            Cipher cifrador = Cipher.getInstance(PADDING);

            byte[] textoClaro = texto.getBytes();
            
            cifrador.init(Cipher.ENCRYPT_MODE, llave, ivSpec);
            textoCifrado = cifrador.doFinal(textoClaro);
            
            return textoCifrado;
        } catch (Exception e) {
            System.out.println("Excepcion: " + e.getMessage());
            return null;
        }
    }
    
    // Método para descifrar usando el IV del servidor
    public static byte[] descifrar(SecretKey llave, byte[] texto, IvParameterSpec ivSpec) {
        byte[] textoClaro;
        try {
            Cipher cifrador = Cipher.getInstance(PADDING);

            cifrador.init(Cipher.DECRYPT_MODE, llave, ivSpec);
            textoClaro = cifrador.doFinal(texto);

        } catch (Exception e) {
            System.out.println("Excepcion: " + e.getMessage());
            return null;
        }
        return textoClaro;
    }

    // llave compartida es (G^y mod p)
    public static ArrayList<SecretKey> generadorLlavesSimetricas(BigInteger secretoCompartido) throws NoSuchAlgorithmException{
        
        MessageDigest sha512;
        sha512 = MessageDigest.getInstance("SHA-512");
        byte[] digest = sha512.digest(secretoCompartido.toByteArray());
        
        byte[] keyAB1Bytes = new byte[32]; 
        byte[] keyAB2Bytes = new byte[32];

        System.arraycopy(digest, 0, keyAB1Bytes, 0, 32); 
        System.arraycopy(digest, 32, keyAB2Bytes, 0, 32); 

        SecretKey keyAB1 = new SecretKeySpec(keyAB1Bytes, "AES");
        SecretKey keyAB2 = new SecretKeySpec(keyAB2Bytes, "AES");

        ArrayList<SecretKey> llaves = new ArrayList<SecretKey>();
        llaves.add(keyAB1);
        llaves.add(keyAB2);

        return llaves;
    }

    // Método para generar HMAC
    public static String generarHMAC(SecretKey llave, String mensaje) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(llave);
            byte[] hmacBytes = mac.doFinal(mensaje.getBytes());
            return Base64.getEncoder().encodeToString(hmacBytes);
        } catch (Exception e) {
            System.err.println("Error al generar HMAC: " + e.getMessage());
            return null;
        }
    }

    public void test() throws Exception {
        // Generar una llave simétrica AES de 256 bits
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey llaveSimetrica = keyGen.generateKey();
    
        // Generar un IV de 16 bytes
        byte[] iv = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
    
        // Mensaje a cifrar
        String mensaje = "Hola, mundo!";
        
        // Cifrar el mensaje
        byte[] mensajeCifrado = cifrar(llaveSimetrica, mensaje, ivSpec);
        System.out.println("Mensaje cifrado: " + new String(mensajeCifrado));
        
        // Descifrar el mensaje
        byte[] mensajeDescifrado = descifrar(llaveSimetrica, mensajeCifrado, ivSpec);
        System.out.println("Mensaje descifrado: " + new String(mensajeDescifrado));
    }
    

    public static void main(String[] args) throws Exception {
        Simetrico simetrico = new Simetrico();
        simetrico.test();
    }
}
