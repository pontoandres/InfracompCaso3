import java.util.Scanner;

public class App {
    // Juan pasó por aquí

    Servidor servidor = new Servidor(4);

    private void opcion1() {
        Servidor.generarLlavesRSA();
    }


    private void mostrarMenu() {
        Scanner scanner = new Scanner(System.in);
        int opcion;
        do {
            System.out.println("Menu:");
            System.out.println("1. Generar Llaves RSA (Opción 1)");
            System.out.println("2. Ejecutar n Clientes Concurrentes (Opción 2)");
            System.out.println("3. Cambiar número de delegados");
            System.out.println("4. Probar mismo cliente, 32 consultas");
            System.out.println("0. Salir");
            System.out.print("Seleccione una opción: ");
            opcion = scanner.nextInt();
            switch (opcion) {
                case 1:
                    opcion1();
                    break;
                case 2:
                    System.out.println("Ingrese número de clientes");
                    int totClientes = scanner.nextInt();
                    System.out.println("Ejecutando clientes concurrentes...");
                    Cliente.ejecutarOpcion2(servidor,totClientes);  
                    break;
                case 3:
                    System.out.println("Ingrese número de clientes");
                    int delegados = scanner.nextInt();
                    servidor.setCantidadDelegados(delegados);
                    break;
                case 4:
                    System.out.println("Ejecutando peticiones...");
                    Cliente.mismoCliente32Consultas();
                    break;
                case 0:
                    System.out.println("Saliendo...");
                    break;
                default:
                    System.out.println("Opción no válida, intente de nuevo.");
            }
        } while (opcion != 0);
        scanner.close();
    }
    


    public static void main(String[] args) throws Exception {
        App app = new App();
        app.mostrarMenu();

        Servidor servidor = new Servidor(0);
        for (int i : new int[]{1, 4, 8, 32}) {
            servidor.setCantidadDelegados(i);
            for (int j : new int[]{1, 4, 8, 32}) {
                Cliente.ejecutarOpcion2(servidor, j);
            }
        }
    }
}
