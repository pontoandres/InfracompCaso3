import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Servidor {

    public static void generarLlavesRSA() {
        try {
            // Generador de llaves RSA de 1024 bits
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            KeyPair parDeLlaves = keyGen.generateKeyPair();
            PrivateKey llavePrivada = parDeLlaves.getPrivate();
            PublicKey llavePublica = parDeLlaves.getPublic();

            // Guardar la llave privada en un archivo
            try (FileOutputStream fos = new FileOutputStream("llavePrivada.key")) {
                fos.write(llavePrivada.getEncoded());
            }

            // Guardar la llave pública en un archivo
            try (FileOutputStream fos = new FileOutputStream("llavePublica.key")) {
                fos.write(llavePublica.getEncoded());
            }

            System.out.println("Las llaves asimétricas se generaron y guardaron exitosamente.");
            System.out.println("La llave privada se guardó en 'llavePrivada.key'.");
            System.out.println("La llave pública se guardó en 'llavePublica.key' y puede ser accedida por los clientes.");
        } catch (NoSuchAlgorithmException | IOException e) {
            System.err.println("Error al generar las llaves: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        // Menú simple para seleccionar la opción 1
        System.out.println("Selecciona una opción:");
        System.out.println("1: Generar la pareja de llaves asimétricas");

        // Para simplificar, asumimos que la opción 1 fue seleccionada
        generarLlavesRSA();
    }
}
