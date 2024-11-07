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
            System.out.println("1. Generar Llaves RSA");
            System.out.println("2. Ejecutar Clientes Concurrentes");
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
    }
}
