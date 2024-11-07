import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
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
import java.util.HashMap;
import java.util.List;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;


public class Servidor extends Thread{

    PrivateKey llavePrivada = null;
    PublicKey llavePublica = null;
    int cantidadDelegados;
    int delegadosOcupados = 0;
    BigInteger llavePrivadaDiffie = new BigInteger(256, new SecureRandom());
    private HashMap<String, HashMap<String, String>> estadoClientesPaquetes;
    private HashMap<String, Cliente> clientesConectados = new HashMap<>();

    // modificar cantidad de delegados

    public synchronized void setCantidadDelegados(int cantidadDelegados) {
        this.cantidadDelegados = cantidadDelegados;
    }

    // ocupar puesto
    public synchronized void ocuparPuesto() {
        while (delegadosOcupados == cantidadDelegados) {
            try {
                wait();
            } catch (InterruptedException e) {
                System.err.println("Error al esperar: " + e.getMessage());
            }
        }
        delegadosOcupados++;
    }
    // liberar puesto
    public synchronized void liberarPuesto() {
        delegadosOcupados--;
        notifyAll();
    }

    // Lista de estados posibles
    private static final String[] ESTADOS = {
        "ENOFICINA", "RECOGIDO", "ENCLASIFICACION", "DESPACHADO",
        "ENENTREGA", "ENTREGADO", "DESCONOCIDO"
    };
    

    public Servidor(int cantidadDelegados) {
        leerLlavesRSA();
        this.cantidadDelegados = cantidadDelegados;
        estadoClientesPaquetes = new HashMap<>();
        Random random = new Random();
    
        // Crear 32 clientes, cada uno con 1 paquete
        for (int clienteId = 1; clienteId <= 32; clienteId++) {
            String clienteKey = String.valueOf(clienteId);
            HashMap<String, String> paquetes = new HashMap<>();
    
            String paqueteId = "paquete" + clienteId;
            String estado = ESTADOS[random.nextInt(ESTADOS.length)];
            paquetes.put(paqueteId, estado);
    
            estadoClientesPaquetes.put(clienteKey, paquetes);
        }
    }

    public synchronized void registrarCliente(Cliente cliente) {
        String clienteId = String.valueOf(cliente.getClienteID());
        clientesConectados.put(clienteId, cliente);
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
        // while (delegadosOcupados == cantidadDelegados) {
        //     try {
        //         wait();
        //     } catch (InterruptedException e) {
        //         System.err.println("Error al esperar: " + e.getMessage());
        //     }
        // }
        // delegadosOcupados++;
        byte[] retoDescifrado = Asimetrico.descifrar(llavePrivada, "RSA", retoCifrado);
        // delegadosOcupados--;
        // notifyAll();
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

        // Generar un IV de 16 bytes y agregarlo a la lista de retorno
        byte[] iv = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);

        diffieHellmanList.add(diffieHellman); // Agregar el objeto DiffieHellman a la lista
        diffieHellmanList.add(textoCifrado); // Agregar el texto cifrado a la lista
        diffieHellmanList.add(iv); // Agregar el IV a la lista de retorno
        
        return diffieHellmanList;
    }
    
    public synchronized boolean checkLlaveCompartida(DiffieHellman dh){

        BigInteger llaveCompartidaOriginal = dh.llaveCompartida;
        BigInteger llaveCompartida = dh.llaveCompartida(dh.llaveCompartidaCliente, llavePrivadaDiffie, dh.prime);
        return llaveCompartida.equals(llaveCompartidaOriginal);
    }

    public synchronized void recibirConsultaPaquete(
        byte[] uidCifrado,
        String hmacUid,
        byte[] paqueteIdCifrado,
        String hmacPaqueteId,
        DiffieHellman dh,
        IvParameterSpec iv
    ) {
        try {
            // Descifrar UID y verificar HMAC
            byte[] uidDescifradoBytes = Simetrico.descifrar(dh.llaveSimetricaAB1, uidCifrado, iv);
            String uidDescifrado = new String(uidDescifradoBytes);
            String hmacUidCalculado = Simetrico.generarHMAC(dh.llaveSimetricaAB2, uidDescifrado);
    
            if (!hmacUidCalculado.equals(hmacUid)) {
                System.err.println("Error en la verificación del HMAC del UID. Datos comprometidos.");
                return;
            }
    
            // Descifrar paqueteId y verificar HMAC
            byte[] paqueteIdDescifradoBytes = Simetrico.descifrar(dh.llaveSimetricaAB1, paqueteIdCifrado, iv);
            String paqueteIdDescifrado = new String(paqueteIdDescifradoBytes);
            String hmacPaqueteIdCalculado = Simetrico.generarHMAC(dh.llaveSimetricaAB2, paqueteIdDescifrado);
    
            if (!hmacPaqueteIdCalculado.equals(hmacPaqueteId)) {
                System.err.println("Error en la verificación del HMAC del paquete ID. Datos comprometidos.");
                return;
            }
    
            // Verificar estado del paquete
            verificarEstadoPaquete(uidDescifrado, paqueteIdDescifrado);
    
            // Obtener el estado del paquete
            String estado = estadoClientesPaquetes
                .getOrDefault(uidDescifrado, new HashMap<>())
                .getOrDefault(paqueteIdDescifrado, "DESCONOCIDO");
    
            // Enviar estado y su HMAC al cliente
            enviarEstadoPaquete(estado, dh, iv, uidDescifrado);
    
        } catch (Exception e) {
            System.err.println("Error al procesar consulta de paquete: " + e.getMessage());
        }
    }
    
    private void enviarEstadoPaquete(String estado, DiffieHellman dh, IvParameterSpec iv, String clienteId) {
        try {

            // Cifrado simétrico
            long startTimeSimetrico = System.nanoTime();
            byte[] estadoCifrado = Simetrico.cifrar(dh.llaveSimetricaAB1, estado, iv);
            long tiempoSimetrico = System.nanoTime() - startTimeSimetrico;
            System.out.println("Tiempo de cifrado simétrico: " + tiempoSimetrico + " ns");

            // Cifrado asimétrico
            long startTimeAsimetrico = System.nanoTime();
            byte[] estadoCifradoAsimetrico = Asimetrico.cifrar(llavePublica, "RSA", estado);
            long tiempoAsimetrico = System.nanoTime() - startTimeAsimetrico;
            System.out.println("Tiempo de cifrado asimétrico: " + tiempoAsimetrico + " ns");

            // Guardar tiempos en archivo
            guardarTiemposEnArchivo(clienteId, tiempoSimetrico, tiempoAsimetrico);


            // Generar HMAC del estado
            String hmacEstado = Simetrico.generarHMAC(dh.llaveSimetricaAB2, estado);
    
            // Obtener el cliente desde el mapa
            Cliente cliente = clientesConectados.get(clienteId);
            if (cliente != null) {
                System.out.println("Servidor: Enviando estado cifrado al cliente " + clienteId);
                cliente.recibirEstadoCifrado(estadoCifrado, hmacEstado);
            } else {
                System.err.println("Cliente con ID " + clienteId + " no está conectado.");
            }
        } catch (Exception e) {
            System.err.println("Error al enviar estado cifrado: " + e.getMessage());
        }
    }    
    
    private synchronized void guardarTiemposEnArchivo(String clienteId, long tiempoSimetrico, long tiempoAsimetrico) {
        String nombreArchivo = "tiempos_ejecucion.txt";  // Un archivo único para todos los clientes
        File archivo = new File(nombreArchivo);
    
        try (FileWriter writer = new FileWriter(archivo, true)) {
            writer.write("Cliente " + clienteId + ": ");
            writer.write("Simétrico: " + tiempoSimetrico + " ns, ");
            writer.write("Asimétrico: " + tiempoAsimetrico + " ns\n");
        } catch (IOException e) {
            System.err.println("Error al guardar tiempos en el archivo: " + e.getMessage());
        }
    }
    

    public synchronized void verificarEstadoPaquete(String clienteId, String paqueteId) {
        HashMap<String, String> paquetesCliente = estadoClientesPaquetes.getOrDefault(clienteId, new HashMap<>());
        String estado = paquetesCliente.getOrDefault(paqueteId, "DESCONOCIDO");
        System.out.println("Servidor: Estado del paquete con ID " + paqueteId + " para el cliente " + clienteId + ": " + estado);
    }    
    
    public synchronized void recibirMensajeTerminacion(String mensaje) {
        if ("TERMINAR".equals(mensaje)) {
            System.out.println("Servidor: Conexión terminada correctamente.");
        } else {
            System.err.println("Servidor: Mensaje de terminación inválido.");
        }
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
