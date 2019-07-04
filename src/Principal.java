import java.util.Scanner;

import org.json.JSONObject;

public class Principal {
	
	/**
	 * Esta aplicación es solo un ejemplo de funcionamiento. Se tiene que adaptar para cada software particular.
	 */

	private static ClienteTFG cliente;
	private static EncryptModule enc;
	
	public static void main(String[] args) {

		Scanner lector = new Scanner(System.in);
		
		enc = new EncryptModule();
		cliente = new ClienteTFG("kaienu","oxgnub", enc);
		cliente.getHilo().start();
		
		while (true) {
			
			String instruccion = lector.nextLine();
			cliente.setInstruccion(new JSONObject().put("peticion", instruccion));
			
			if (instruccion.equalsIgnoreCase("exit") || instruccion.equalsIgnoreCase("poweroff")) {
				System.out.println("Main: Saliendo");
				cliente.running = false;
				break;
			}
			
		}
		
		lector.close();
		
	}
	
	public static void stopConexion() {
		cliente.setInstruccion(new JSONObject().put("peticion", "exit"));
	}

}
