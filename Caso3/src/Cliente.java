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
import java.util.concurrent.CountDownLatch;

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
    private IvParameterSpec iv; // almacenar el IV recibido
    private String paqueteId;

    

    public Cliente(Servidor servidor, int clienteID, String paqueteId){  
        reto = new BigInteger(130, new java.security.SecureRandom());
        leerLlavePublicaRSA();
        simetrico = new Simetrico();
        retoString = reto.toString();
        this.servidor = servidor;
        this.ClienteID = clienteID;
        this.textoBase = "Cliente " + ClienteID + " - ";
        this.llavePrivada = new BigInteger(256, new java.security.SecureRandom());
        this.paqueteId = paqueteId;
        
    }
    public int getClienteID(){
        return ClienteID;
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
        servidor.ocuparPuesto();
        long totalSum = 0;
        long startTime = System.currentTimeMillis();


        System.out.println(textoBase+"Iniciando conexión con el servidor...");
        
        if(descifrarReto(cifrarReto()).equals(retoString)){
            System.out.println(textoBase+"conexión reto: OK");
            totalSum+= (System.currentTimeMillis()-startTime);
            tiempoDescifrarReto = (""+totalSum+"\n"); // toma tiempo descifrado
            
            pedirLlavesPublicas();
            
            // AGREGAR AQUÍ DEMÁS KONEKSIONES @Ponto
            enviarConsultaPaquete(paqueteId);



        } else {
            System.out.println(textoBase+"conexión reto: ERROR");
        }
        
        System.out.println(tiempoDescifrarReto+"\n"+tiempoGenerarGP);
        servidor.liberarPuesto();
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
            byte[] ivBytes = (byte[]) listaDiffie.get(2);
            this.iv = new IvParameterSpec(ivBytes);   

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

    private void enviarConsultaPaquete(String paqueteId) {
        try {
            // Preparar UID y cifrar
            String uid = String.valueOf(ClienteID);
            byte[] uidCifrado = Simetrico.cifrar(dh.llaveSimetricaAB1, uid, this.iv);
            String hmacUid = Simetrico.generarHMAC(dh.llaveSimetricaAB2, uid);
    
            // Preparar paqueteId y cifrar
            byte[] paqueteIdCifrado = Simetrico.cifrar(dh.llaveSimetricaAB1, paqueteId, this.iv);
            String hmacPaqueteId = Simetrico.generarHMAC(dh.llaveSimetricaAB2, paqueteId);
    
            // Enviar todo al servidor
            servidor.recibirConsultaPaquete(uidCifrado, hmacUid, paqueteIdCifrado, hmacPaqueteId, dh, this.iv);
    
        } catch (Exception e) {
            System.err.println("Error al enviar consulta de paquete: " + e.getMessage());
        }
    }
    
    public void recibirEstadoCifrado(byte[] estadoCifrado, String hmacEstado) {
        try {
            // Descifrar el estado
            String estadoDescifrado = new String(Simetrico.descifrar(dh.llaveSimetricaAB1, estadoCifrado, iv));
    
            // Verificar el HMAC
            String hmacCalculado = Simetrico.generarHMAC(dh.llaveSimetricaAB2, estadoDescifrado);
    
            if (hmacEstado.equals(hmacCalculado)) {
                System.out.println(textoBase + "Estado del paquete: " + estadoDescifrado);
            } else {
                System.err.println(textoBase + "Error en la verificación del HMAC del estado.");
            }
    
            // Enviar mensaje de terminación
            enviarMensajeTerminacion();
    
        } catch (Exception e) {
            System.err.println(textoBase + "Error al procesar estado cifrado: " + e.getMessage());
        }
    }

    private void enviarMensajeTerminacion() {
        servidor.recibirMensajeTerminacion("TERMINAR");
        System.out.println(textoBase + "Mensaje de terminación enviado.");
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
    
    
    
    public static void ejecutarOpcion2(Servidor servidor, int totClientes){ {
        System.out.println("Cliente");
    
        Cliente cliente = new Cliente(servidor, 0, "paquete0");
        
        int tot = totClientes;
        cliente.setTotClientes(tot);
    
        CountDownLatch latch = new CountDownLatch(tot);
    
        // Crear 32 clientes concurrentes
        for (int i = 0; i < tot; i++) {
            final int clientId = i + 1;
            final String paqueteId = "paquete" + clientId;
    
            new Thread(() -> {
                Cliente clienteConcurrente = new Cliente(servidor, clientId, paqueteId);
                servidor.registrarCliente(clienteConcurrente); 
                clienteConcurrente.conexionServidor();
                
                latch.countDown();
            }).start();
        }
    
        try {
            latch.await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    
        System.out.println("Todos los clientes han terminado.");
    }
}



}
