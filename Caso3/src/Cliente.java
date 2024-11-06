import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

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
    private BigInteger llavePrivada;
    private String tiempoDescifrarReto = "";
    private String tiempoGenerarGP = "";
    private String tiempoVerificarFirma = "";
    private static int totClientes ;
    

    public Cliente(Servidor servidor, int clienteID) { 
        reto = new BigInteger(130, new java.security.SecureRandom());
        leerLlavePublicaRSA();
        simetrico = new Simetrico();
        retoString = reto.toString();
        this.servidor = servidor;
        this.ClienteID = clienteID;
        this.textoBase = "Cliente " + ClienteID + " - ";
        this.llavePrivada = new BigInteger(1024, new java.security.SecureRandom());
        
    }

    public void setTotClientes(int a){
        totClientes = a;
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
        long totalSum = 0;
        long startTime = System.currentTimeMillis();


        System.out.println(textoBase+"Iniciando conexión con el servidor...");
        
        if(descifrarReto(cifrarReto()).equals(retoString)){
            System.out.println(textoBase+"conexión reto: OK");
            totalSum+= (System.currentTimeMillis()-startTime);
            tiempoDescifrarReto = (""+totalSum+"\n"); // toma tiempo descifrado
            
            pedirLlavesPublicas();
            
            // AGREGAR AQUÍ DEMÁS KONEKSIONES @Ponto




        } else {
            System.out.println(textoBase+"conexión reto: ERROR");
        }
        
        System.out.println(tiempoDescifrarReto+"\n"+tiempoGenerarGP);
    }

    // fin parte 1

    // Parte 2: Diffie Hellman

    private void pedirLlavesPublicas(){
        System.out.println(textoBase+"Iniciando DiffieHellman...");
        // this.dh = new DiffieHellman();
        
        long totalSum = 0;
        long startTime = System.currentTimeMillis();

        ArrayList<Object> listaDiffie = this.servidor.iniciarDiffieHellman();

        totalSum+= (System.currentTimeMillis()-startTime);
        tiempoGenerarGP = (""+totalSum+"\n"); // tiempo generar G, P g^x

        this.dh = (DiffieHellman) listaDiffie.get(0);
        System.out.println(textoBase+"Creado DiffieHellman...");

        // establecer llave compartida cliente
        BigInteger llaveComunicado = dh.llaveAComunicar(dh.generator, dh.prime, llavePrivada);
        dh.setLlaveCompartidaCliente(llaveComunicado);

        // establecer llave compartida general

        dh.llaveCompartida(dh.llaveCompartidaServidor, llavePrivada, dh.prime);



        // verificar firma
        startTime = System.currentTimeMillis();

        byte[] firmaServidor = (byte[]) listaDiffie.get(1);
        String firma = new String(Asimetrico.descifrar(llavePublica, "RSA", firmaServidor));
        String firmaEsperada = ""+dh.prime.intValue()+":"+dh.generator+":"+dh.llaveCompartidaServidor.intValue();

        totalSum+= (System.currentTimeMillis()-startTime);
        tiempoVerificarFirma = (""+totalSum+"\n"); // tiempo verificar firma
        
        if (firma.equals(firmaEsperada)){
            System.out.println(textoBase+"Firma con DiffieHellman: OK");
            
            // recibir y usar el IV del servidor
            byte[] iv = (byte[]) listaDiffie.get(2);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);   

            // crear llaves simetricas
            this.dh.setLlavesSimetricas();
            System.out.println(textoBase+"Llave simétrica creada: ");

            // verificar llaves compartidas
            if (this.servidor.checkLlaveCompartida(dh)){
                System.out.println(textoBase+"Llave compartidas simetricas: OK");
            } else {
                System.out.println(textoBase+"Llave compartida: ERROR");
            }
            

        } else {
            System.out.println(textoBase+" Firma con DiffieHellman: ERROR");
        }

    }

    // fin parte 2


    // generacion archivos

    public void generarArchivos(){
        String nombreCarpeta = ""+this.servidor.cantidadDelegados+"Delegados"+this.totClientes+"Cliente-Pruebas";
        generarArchivos(tiempoDescifrarReto,nombreCarpeta,"TiempoDescifrarReto");
        generarArchivos(tiempoGenerarGP,nombreCarpeta,"TiempoGenerarGP");
        generarArchivos(tiempoVerificarFirma, nombreCarpeta,"TiempoVerificarFirma");
    }

    private void generarArchivos(String contenido, String nombreCarpeta, String nombreArchivo) {
        // Crear la carpeta si no existe
        File carpeta = new File(nombreCarpeta);
        if (!carpeta.exists()) {
            carpeta.mkdir();
        }

        // Crear el archivo dentro de la carpeta
        File archivo = new File(carpeta, nombreArchivo);
        try (FileWriter writer = new FileWriter(archivo,true)) {
            writer.write(contenido);
            System.out.println("Archivo guardado exitosamente en: " + archivo.getAbsolutePath());
        } catch (IOException e) {
            System.out.println("Ocurrió un error al guardar el archivo: " + e.getMessage());
        }
    }
    
    
    
    public static void main(String[] args) {
        System.out.println("Cliente");
        Servidor servidor = new Servidor(4);
        Cliente cliente = new Cliente(servidor, 0);
        // cliente.conexionServidor();


        int tot = 32;
        cliente.setTotClientes(tot);

        
        // descomentar para probar con 32 clientes concurrentes 
        for (int i = 0; i < tot; i++) {
            final int clientId = i + 1;
            new Thread(() -> {
            Cliente clienteConcurrente = new Cliente(servidor, clientId);
            clienteConcurrente.conexionServidor();
            clienteConcurrente.generarArchivos();
            }).start();
        }
    }



}
