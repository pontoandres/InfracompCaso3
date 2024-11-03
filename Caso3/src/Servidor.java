import java.io.File;
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

            // Crear un directorio para la llave privada si no existe
            File privateDir = new File("privado");
            if (!privateDir.exists()) {
                if (privateDir.mkdir()) {
                    System.out.println("Directorio 'privado' creado exitosamente.");
                } else {
                    System.err.println("No se pudo crear el directorio 'privado'.");
                    return; // Detener si no se puede crear el directorio
                }
            }

            // Guardar la llave privada en el directorio 'privado'
            try (FileOutputStream fos = new FileOutputStream("privado/llavePrivada.key")) {
                fos.write(llavePrivada.getEncoded());
            }

            // Crear un directorio para la llave pública si no existe
            File publicDir = new File("publico");
            if (!publicDir.exists()) {
                if (publicDir.mkdir()) {
                    System.out.println("Directorio 'publico' creado exitosamente.");
                } else {
                    System.err.println("No se pudo crear el directorio 'publico'.");
                    return; // Detener si no se puede crear el directorio
                }
            }

            // Guardar la llave pública en el directorio 'publico'
            try (FileOutputStream fos = new FileOutputStream("publico/llavePublica.key")) {
                fos.write(llavePublica.getEncoded());
            }

            System.out.println("Las llaves asimétricas se generaron y guardaron exitosamente.");
            System.out.println("La llave privada se guardó en 'privado/llavePrivada.key'.");
            System.out.println("La llave pública se guardó en 'publico/llavePublica.key' y puede ser accedida por los clientes.");
        } catch (NoSuchAlgorithmException | IOException e) {
            System.err.println("Error al generar las llaves: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        // Menú simple para seleccionar la opción 1
        System.out.println("Selecciona una opción:");
        System.out.println("1: Generar la pareja de llaves asimétricas");

        // TODO: Implementar la opción 1 EN CONSOLA
        generarLlavesRSA();
    }
}
