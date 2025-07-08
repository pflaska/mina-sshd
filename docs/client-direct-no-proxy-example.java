/**
 * Example: Connecting with Apache Mina SSHD SshClient without any proxy (direct connection).
 *  
 * Remove any calls to setClientProxyConnector or set it to null to ensure no proxy is used.
 */
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;

public class DirectNoProxyExample {
    public static void main(String[] args) throws Exception {
        String sshHost = "ssh.example.com";
        int sshPort = 22;

        SshClient client = SshClient.setUpDefaultClient();
        // No proxy connector set: this is the default behavior
        // client.setClientProxyConnector(null); // explicit if you previously set one
        client.start();

        try (ClientSession session = client.connect("username", sshHost, sshPort)
            .verify(15000)
            .getSession()) {
            session.addPasswordIdentity("password");
            session.auth().verify(10000);
            // Proceed with normal SSH operations...
        } finally {
            client.stop();
        }
    }
}
