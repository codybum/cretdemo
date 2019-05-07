import com.google.gson.Gson;

public class Launcher {


    public static Gson gson;

    public static void main(String[] args)  {



       try {


           CertificateManager certificateManager = new CertificateManager();


       } catch(Exception ex) {
            ex.printStackTrace();
        }

    }

}
