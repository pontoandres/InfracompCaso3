import java.util.Scanner;

public class App {
    // Juan pasó por aquí

    Servidor servidor = new Servidor();

    private void opcion1() {
        Servidor.generarLlavesRSA();
    }


    private void mostrarMenu() {
        Scanner scanner = new Scanner(System.in);
        int opcion;
        do {
            System.out.println("Menu:");
            System.out.println("1. Opción 1");
            System.out.println("2. Opción 2");
            System.out.println("0. Salir");
            System.out.print("Seleccione una opción: ");
            opcion = scanner.nextInt();
            switch (opcion) {
                case 1:
                    opcion1();
                    break;
                case 2:
                    // Implementar opción 2
                    System.out.println("Opción 2 seleccionada");
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
