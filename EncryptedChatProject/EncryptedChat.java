import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class EncryptedChat {
    private static PublicKey publicPartnerKey;
    private static PrivateKey privateKey;
    private static PublicKey publicKey;

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        // Generate keys
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        System.out.print("Do you want to host(1) or connect(2): ");
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
            String choice = reader.readLine().trim(); // Read and trim any extra whitespace
            System.out.println("User choice: " + choice); // Debug print
            startChat(choice);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void startChat(String choice) {
        if (choice.equals("1")) {
            startServer();
        } else if (choice.equals("2")) {
            startClient();
        } else {
            System.out.println("Invalid choice.");
        }
    }

    private static void startServer() {
        try (ServerSocket serverSocket = new ServerSocket(9999)) {
            System.out.println("Waiting for a connection...");
            try (Socket client = serverSocket.accept();
                    DataInputStream input = new DataInputStream(client.getInputStream());
                    DataOutputStream output = new DataOutputStream(client.getOutputStream())) {

                System.out.println("Sending public key...");
                output.writeUTF(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
                System.out.println("Receiving public key...");
                publicPartnerKey = KeyFactory.getInstance("RSA")
                        .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(input.readUTF())));
                System.out.println("Connected to partner.");
                handleChat(client, input, output);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void startClient() {
        try (Socket client = new Socket("localhost", 9999);
                DataInputStream input = new DataInputStream(client.getInputStream());
                DataOutputStream output = new DataOutputStream(client.getOutputStream())) {

            System.out.println("Receiving public key...");
            publicPartnerKey = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(input.readUTF())));
            System.out.println("Sending public key...");
            output.writeUTF(Base64.getEncoder().encodeToString(publicKey.getEncoded()));

            System.out.println("Connected to partner.");
            handleChat(client, input, output);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void handleChat(Socket client, DataInputStream input, DataOutputStream output) {
        Thread sendThread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
                while (true) {
                    String message = reader.readLine();
                    if (message.equalsIgnoreCase("exit")) {
                        output.writeUTF(encryptMessage(message, publicPartnerKey));
                        break;
                    }
                    output.writeUTF(encryptMessage(message, publicPartnerKey));
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        Thread receiveThread = new Thread(() -> {
            try {
                while (true) {
                    String encryptedMessage = input.readUTF();
                    String message = decryptMessage(encryptedMessage, privateKey);
                    if (message.equalsIgnoreCase("exit")) {
                        break;
                    }
                    System.out.println("Partner: " + message);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        sendThread.start();
        receiveThread.start();

        try {
            sendThread.join();
            receiveThread.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    private static String encryptMessage(String message, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decryptMessage(String message, PrivateKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(message));
        return new String(decryptedBytes);
    }
}
