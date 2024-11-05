import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Semaphore;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DiffieHellman {
    private static final Semaphore semaphore = new Semaphore(10);
    public BigInteger prime;
    public int generator;
    public BigInteger llaveCompartida;

    String output = "";

    public DiffieHellman() {
        try {
            iniciarProceso();
        } catch (IOException | InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        parser(output);
    }

    public synchronized void iniciarProceso() throws IOException, InterruptedException {

        String executablePath = "OpenSSL-1.1.1h_win32\\openssl.exe";
        String[] command = { executablePath, "dhparam", "-text", "1024" };
        
        // Process process = Runtime.getRuntime().exec(command);
        Process process = new ProcessBuilder().command(command).redirectErrorStream(true).start();

        
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        reader.close();
        
        process.waitFor();
        this.output = output.toString();
    }
    
    public void parser(String input) {

        Pattern primePattern = Pattern.compile("prime:\\s*([0-9a-fA-F:\\s]+)");
        Matcher primeMatcher = primePattern.matcher(input);

        Pattern generatorPattern = Pattern.compile("generator:\\s*(\\d+)");
        Matcher generatorMatcher = generatorPattern.matcher(input);

        if (primeMatcher.find()) {
            String hexPrime = primeMatcher.group(1).replaceAll("[:\\s]", "");
            this.prime = new BigInteger(hexPrime, 16); 
        }

        if (generatorMatcher.find()) {
            this.generator = Integer.parseInt(generatorMatcher.group(1));
        }
        System.out.println("Primo: " + this.prime + "\nGenerador: " + this.generator);
    }

    public BigInteger llaveAComunicar(int generator, BigInteger prime, BigInteger llavePrivada) {
        return BigInteger.valueOf(generator).modPow(llavePrivada, prime);
    }

    public BigInteger llaveCompartida(BigInteger llaveComunicada, BigInteger llavePrivada, BigInteger prime) {
        this.llaveCompartida = llaveComunicada.modPow(llavePrivada, prime);
        return llaveComunicada.modPow(llavePrivada, prime);
    }

    public static void main(String[] args) {
        DiffieHellman diffieHellman = new DiffieHellman();
        try {
            diffieHellman.iniciarProceso();
            System.out.println(diffieHellman.output);
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
        System.out.println("Primo: " + diffieHellman.prime);
        System.out.println("Generador: " + diffieHellman.generator);

        BigInteger llavePrivadaA = new BigInteger(1024, new SecureRandom());
        BigInteger llavePrivadaB = new BigInteger(1024, new SecureRandom());

        BigInteger llaveComunicadaA = diffieHellman.llaveAComunicar(diffieHellman.generator, diffieHellman.prime, llavePrivadaA);
        BigInteger llaveComunicadaB = diffieHellman.llaveAComunicar(diffieHellman.generator, diffieHellman.prime, llavePrivadaB);

        BigInteger llaveCompartidaA = diffieHellman.llaveCompartida(llaveComunicadaB, llavePrivadaA, diffieHellman.prime);
        BigInteger llaveCompartidaB = diffieHellman.llaveCompartida(llaveComunicadaA, llavePrivadaB, diffieHellman.prime);

        System.out.println("Llave compartida A: " + llaveCompartidaA);
        System.out.println("Llave compartida B: " + llaveCompartidaB);

        try {
            System.out.println(Simetrico.generadorLlavesSimetricas(llaveCompartidaB).equals(Simetrico.generadorLlavesSimetricas(llaveCompartidaA)));
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }


        
    }
}
