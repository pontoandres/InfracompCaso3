import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.math.BigInteger;

public class Cliente extends Thread{
    // Juan pasó por aquí
    private BigInteger reto;
    private String retoString;
    private PublicKey llavePublica;
    private Simetrico simetrico;
    private Servidor servidor;
    private int ClienteID;
    private String textoBase;
    private DiffieHellman dh;

    public Cliente(Servidor servidor, int clienteID) { 
        reto = new BigInteger(130, new java.security.SecureRandom());
        leerLlavePublicaRSA();
        simetrico = new Simetrico();
        retoString = reto.toString();
        this.servidor = servidor;
        this.ClienteID = clienteID;
        this.textoBase = "Cliente " + ClienteID + " - ";
        

    }   

    private void leerLlavePublicaRSA(){

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
        this.llavePublica = keyFactory.generatePublic(publicKeySpec);

        // System.out.println("La llave pública se leyó exitosamente desde 'publico/llavePublica.key'.");
        // System.out.println("La llave pública es: " + llavePublica);
    } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
        System.err.println("Error al leer la llave pública: " + e.getMessage());
    }
    }


    // Parte 1: Reto.
    private byte[] cifrarReto(){
        byte[] retoCifrado = Asimetrico.cifrar(llavePublica, "RSA", new String(retoString));
        return retoCifrado;
    }

    private String descifrarReto(byte[] retoCifrado){
        byte[] retoDescifrado = this.servidor.descifrarReto(retoCifrado);
        return new String(retoDescifrado);

    }

    private void conexionServidor(){
        System.out.println(textoBase+"Iniciando conexión con el servidor...");
        
        if(descifrarReto(cifrarReto()).equals(retoString)){
            System.out.println(textoBase+"conexión reto: OK");
            pedirLlavesPublicas();
        } else {
            System.out.println(textoBase+"conexión reto: ERROR");
        }
    }

    // fin parte 1

    // Parte 2: Diffie Hellman

    private void pedirLlavesPublicas(){
        System.out.println(textoBase+"Iniciando DiffieHellman...");
        this.dh = new DiffieHellman();
        System.out.println(textoBase+"Creado DiffieHellman...");
    }

    // fin parte 2

    
    
    public static void main(String[] args) {
        System.out.println("Cliente");
        Servidor servidor = new Servidor(32);
        Cliente cliente = new Cliente(servidor, 1);
        cliente.conexionServidor();

        // descomentar para probar con 32 clientes concurrentes 
        for (int i = 0; i < 32; i++) {
            final int clientId = i + 1;
            new Thread(() -> {
            Cliente clienteConcurrente = new Cliente(servidor, clientId);
            clienteConcurrente.conexionServidor();
            }).start();
        }
    }



}
