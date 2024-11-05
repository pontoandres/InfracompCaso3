import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;

import javax.crypto.KeyGenerator;

public class Simetrico {

    // Constante para el cifrado
    private final static String PADDING = "AES/CBC/PKCS5Padding";
    
    // Método para cifrar con IV
    public static byte[] cifrar(SecretKey llave, String texto) {
        byte[] textoCifrado;
        try {
            Cipher cifrador = Cipher.getInstance(PADDING);
            
            // Generar un IV de 16 bytes aleatoriamente
            byte[] iv = new byte[16];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            byte[] textoClaro = texto.getBytes();
            
            cifrador.init(Cipher.ENCRYPT_MODE, llave, ivSpec);
            textoCifrado = cifrador.doFinal(textoClaro);

            // Concatenar el IV al inicio del texto cifrado para usarlo en el descifrado
            byte[] resultado = new byte[iv.length + textoCifrado.length];
            System.arraycopy(iv, 0, resultado, 0, iv.length);
            System.arraycopy(textoCifrado, 0, resultado, iv.length, textoCifrado.length);
            
            return resultado;
        } catch (Exception e) {
            System.out.println("Excepcion: " + e.getMessage());
            return null;
        }
    }
    
    // Método para descifrar usando el IV del texto cifrado
    public static byte[] descifrar(SecretKey llave, byte[] texto) {
        byte[] textoClaro;
        try {
            Cipher cifrador = Cipher.getInstance(PADDING);
            
            // Extraer el IV del texto cifrado
            byte[] iv = new byte[16];
            System.arraycopy(texto, 0, iv, 0, 16);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            
            // Extraer el texto cifrado sin el IV
            byte[] textoCifradoSinIV = new byte[texto.length - 16];
            System.arraycopy(texto, 16, textoCifradoSinIV, 0, texto.length - 16);

            cifrador.init(Cipher.DECRYPT_MODE, llave, ivSpec);
            textoClaro = cifrador.doFinal(textoCifradoSinIV);

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

    public void test() throws Exception {
        // Generar una llave simétrica AES de 256 bits
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey llaveSimetrica = keyGen.generateKey();


        // Mensaje a cifrar
        String mensaje = "Hola, mundo!";
        
        // Cifrar el mensaje
        byte[] mensajeCifrado = cifrar(llaveSimetrica, mensaje);
        System.out.println("Mensaje cifrado: " + new String(mensajeCifrado));
        
        // Descifrar el mensaje
        byte[] mensajeDescifrado = descifrar(llaveSimetrica, mensajeCifrado);
        System.out.println("Mensaje descifrado: " + new String(mensajeDescifrado));
    }

    public static void main(String[] args) throws Exception {
        Simetrico simetrico = new Simetrico();
        simetrico.test();
    }
}
