import javax.crypto.Cipher;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Asimetrico {

    // Método para cifrar
    public static byte[] cifrar(Key llave, String algoritmo, String texto) {
        byte[] textoCifrado;
        try {
            Cipher cifrador = Cipher.getInstance(algoritmo);
            byte[] textoClaro = texto.getBytes();

            cifrador.init(Cipher.ENCRYPT_MODE, llave);
            textoCifrado = cifrador.doFinal(textoClaro);

            return textoCifrado;
        } catch (Exception e) {
            System.out.println("Excepcion: " + e.getMessage());
            return null;
        }
    }

    // Método para descifrar
    public static byte[] descifrar(Key llave, String algoritmo, byte[] texto) {
        byte[] textoClaro;
        try {
            Cipher cifrador = Cipher.getInstance(algoritmo);
            cifrador.init(Cipher.DECRYPT_MODE, llave);
            textoClaro = cifrador.doFinal(texto);

        } catch (Exception e) {
            System.out.println("Excepcion: " + e.getMessage());
            return null;
        }
        return textoClaro;
    }

    public void test() throws NoSuchAlgorithmException {
        // Crear un par de llaves RSA
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            KeyPair parDeLlaves = keyGen.generateKeyPair();
            PrivateKey llavePrivada = parDeLlaves.getPrivate();
            PublicKey llavePublica = parDeLlaves.getPublic();


        // Cifrar un mensaje con la llave pública
        String mensaje = "Hola, mundo!";
        byte[] mensajeCifrado = Asimetrico.cifrar(llavePublica, "RSA", mensaje);
        System.out.println("Mensaje cifrado: " + new String(mensajeCifrado));
        // Descifrar el mensaje con la llave privada
        byte[] mensajeDescifrado = Asimetrico.descifrar(llavePrivada, "RSA", mensajeCifrado);

        // Imprimir el mensaje descifrado
        System.out.println(new String(mensajeDescifrado));
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        Asimetrico asimetrico = new Asimetrico();
        asimetrico.test();
    }
}
