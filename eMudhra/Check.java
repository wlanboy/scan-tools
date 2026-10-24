import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

// Prüft, ob die JVM den kompromittierten eMudhra-Intermediates noch vertraut.
// Aufruf ohne Kompilieren: java Check.java (Java 11+). Exit-Code 1 = verwundbar.
public class Check {
    static final String[] HOSTS = {"dv-g3b", "dv-g3b-aaa", "dv-g3b-noct", "dv-g3b-aaa-noct"};

    public static void main(String[] args) throws Exception {
        var client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
        boolean vulnerable = false;
        System.out.println(System.getProperty("java.vm.vendor") + " " + System.getProperty("java.runtime.version"));
        for (var h : HOSTS) {
            var url = "https://" + h + "-emudhra.we-have-a-problem.com/";
            try {
                var r = client.send(HttpRequest.newBuilder(URI.create(url)).build(), HttpResponse.BodyHandlers.discarding());
                System.out.println("VULNERABEL " + r.statusCode() + " " + url);
                vulnerable = true;
            } catch (Exception e) {
                System.out.println("ok         " + url + " " + e.getMessage());
            }
        }
        System.exit(vulnerable ? 1 : 0);
    }
}
