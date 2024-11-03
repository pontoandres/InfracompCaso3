import javax.crypto.Cipher;
import java.security.Key;

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
}
