import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.KeyStore.SecretKeyEntry;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import javax.crypto.SecretKey;


public class Servidor extends Thread{

    PrivateKey llavePrivada = null;
    PublicKey llavePublica = null;
    int cantidadDelegados;
    int delegadosOcupados = 0;
    BigInteger llavePrivadaDiffie = new BigInteger(1024, new SecureRandom());
    


    public Servidor(int cantidadDelegados) {
        leerLlavesRSA();
        this.cantidadDelegados = cantidadDelegados;
    }



    public static void generarLlavesRSA() {
        try {
            // Generador de llaves RSA de 1024 bits
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            KeyPair parDeLlaves = keyGen.generateKeyPair();
            PrivateKey llavePrivada = parDeLlaves.getPrivate();
            PublicKey llavePublica = parDeLlaves.getPublic();

            // System.out.println("Llave privada: " + llavePrivada);
            // System.out.println("Llave pública: " + llavePublica);
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

    public void leerLlavesRSA() {
    
    try {
        // Leer la llave privada desde el archivo
        File privateKeyFile = new File("privado/llavePrivada.key");
        byte[] privateKeyBytes = new byte[(int) privateKeyFile.length()];
        try (FileInputStream fis = new FileInputStream(privateKeyFile)) {
        fis.read(privateKeyBytes);
        }

        // Convertir los bytes leídos a una llave privada
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        llavePrivada = keyFactory.generatePrivate(privateKeySpec);
        // System.out.println("La llave privada es: " + llavePrivada);


        // System.out.println("La llave privada se leyó exitosamente desde 'privado/llavePrivada.key'.");
    } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
        System.err.println("Error al leer la llave privada: " + e.getMessage());
    }

    
    try {
        // Leer la llave pública desde el archivo
        File publicKeyFile = new File("publico/llavePublica.key");
        byte[] publicKeyBytes = new byte[(int) publicKeyFile.length()];
        try (FileInputStream fis = new FileInputStream(publicKeyFile)) {
            fis.read(publicKeyBytes);
        }

        // Convertir los bytes leídos a una llave pública
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        llavePublica = keyFactory.generatePublic(publicKeySpec);

        // System.out.println("La llave pública se leyó exitosamente desde 'publico/llavePublica.key'.");
        // System.out.println("La llave pública es: " + llavePublica);
    } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
        System.err.println("Error al leer la llave pública: " + e.getMessage());
    }
    }


    // Parte 1: Lectura reto

    public synchronized byte[] descifrarReto(byte[] retoCifrado) {
        while (delegadosOcupados == cantidadDelegados) {
            try {
                wait();
            } catch (InterruptedException e) {
                System.err.println("Error al esperar: " + e.getMessage());
            }
        }
        delegadosOcupados++;
        byte[] retoDescifrado = Asimetrico.descifrar(llavePrivada, "RSA", retoCifrado);
        delegadosOcupados--;
        notifyAll();
        return retoDescifrado;
    }

    // fin parte 1

    // Inicio parte 2 - Diffie Hellman

    public ArrayList<Object> iniciarDiffieHellman() {
        DiffieHellman diffieHellman = new DiffieHellman();
        ArrayList<Object> diffieHellmanList = new ArrayList<Object>();

        

        int generador = diffieHellman.generator;
        BigInteger primo = diffieHellman.prime;
        BigInteger llaveComunicada = diffieHellman.llaveAComunicar(diffieHellman.generator, diffieHellman.prime, llavePrivadaDiffie);
        
        diffieHellman.setLlaveCompartidaServidor(llaveComunicada);

        String textoDiffie = ""+primo.intValue()+":"+generador+":"+llaveComunicada.intValue();
        // System.out.println("Texto Diffie: " + textoDiffie);
        byte[] textoCifrado = Asimetrico.cifrar(llavePrivada, "RSA", textoDiffie);

        diffieHellmanList.add(diffieHellman); // Agregar el objeto DiffieHellman a la lista
        diffieHellmanList.add(textoCifrado); // Agregar el texto cifrado a la lista

        return diffieHellmanList;
    }
    
    public synchronized boolean checkLlaveCompartida(DiffieHellman dh){

        BigInteger llaveCompartidaOriginal = dh.llaveCompartida;
        BigInteger llaveCompartida = dh.llaveCompartida(dh.llaveCompartidaCliente, llavePrivadaDiffie, dh.prime);
        return llaveCompartida.equals(llaveCompartidaOriginal);
    }


    // fin parte 2


    public static void main(String[] args) {
        Servidor servidor = new Servidor(1);

        // Menú simple para seleccionar la opción 1
        System.out.println("Selecciona una opción:");
        System.out.println("1: Generar la pareja de llaves asimétricas");

        // TODO: Implementar la opción 1 EN CONSOLA
        generarLlavesRSA();

        servidor.leerLlavesRSA();

    }
}
