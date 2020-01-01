import java.security.NoSuchAlgorithmException;

public class SSD {
    public static void main (String args[]){
        //exemple ex = new exemple();
        try {
            SSDProjectV1 ssd = new SSDProjectV1();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}
