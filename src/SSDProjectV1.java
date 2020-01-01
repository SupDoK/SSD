import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;

import static java.nio.charset.StandardCharsets.UTF_8;

public class SSDProjectV1 {

    public SSDProjectV1() throws NoSuchAlgorithmException {
        //CONVERTIR TOUS LES STRING EN CHAR
        Scanner sc = new Scanner(System.in);
        String mail;
        String password;

        byte[][] ivCache = new byte[50][];

        char ans;//Char sinon exception avec un int quand on rentre un char
        int ansMail;
        int tempSecret = -1;
        int upThread = 10000;

        int temp = 0;
        int i = 1;
        int j = 0;
        int k = 0;

        //int k = 0;

        try {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            char[] pwdArray = "password".toCharArray();
            ks.load(null, pwdArray);

            try (FileOutputStream fos = new FileOutputStream("newKeyStoreFileName.jks")) {
                ks.store(fos, pwdArray);
            }


        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        //Generation of onTheFly keys
        PublicKey publicKey;
        PrivateKey privateKey;

        KeyPairGenerator PrivkeyGen = null;

        PrivkeyGen = KeyPairGenerator.getInstance("RSA");
        PrivkeyGen.initialize(4096);
        KeyPair pair = PrivkeyGen.generateKeyPair();

        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();

        System.out.println("Assymetric keys generated !");

        DateFormat df = new SimpleDateFormat("yyyy-MM-dd-hh-mm-ss");

        System.out.println("Please enter your credentials");
        System.out.println("Mail :");
        mail = sc.next();
        sc.reset();
        System.out.println("Password : ");
        //saltedHash
        String hashedPWD = sha256(mail+sc.next());


        sc.reset();
        //ENVOIE DEMANDE AU SERVEUR POUR
        //Recup le mdp et l'adresse mail (en recherchant celle que la personne à donnée) dans la db et tester les credentials
        TestConnection();//Test pour verif connexion internet !!!

        Socket socket2 = null;
        try {
            socket2 = new Socket("192.168.56.1", 9000);
            ObjectOutputStream oout=new ObjectOutputStream(socket2.getOutputStream());
            ObjectInputStream iin = new ObjectInputStream(socket2.getInputStream());

            String hello = "Client Hello";

            //TimedObject toSend3 = new TimedObject(dateobj , sign(hello , privateKey) );

            oout.writeObject(hello);
            oout.writeObject(publicKey);
            oout.writeObject( sign(hello , privateKey));

            //Verify certificate !
            X509Certificate cert = (X509Certificate)iin.readObject();
            if(!cert.getIssuerDN().getName().equals("EMAILADDRESS=alphatangototo789@gmail.com, CN=SSD, OU=SSD, O=Crochez ssd, L=Bruxelles, ST=Bruxelles, C=BE")){
                throw  new CertificateException();
            }
            if (cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
                cert.verify(cert.getPublicKey());
                System.out.println("Verified: " + cert.getSubjectX500Principal());
            }

            System.out.println(cert.getPublicKey());

            //AES key generator

            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256); // for example
            SecretKey secretKey = keyGen.generateKey();

            /*
            //Encrypt data with AES
            Cipher cipherAlpha = Cipher.getInstance("AES/CBC/PKCS7PADDING");
            //Check if IF is good and secure
            cipherAlpha.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(secretKey.getEncoded()));

            byte[] encryptedWithAES = cipherAlpha.doFinal(user.toString().getBytes());

            String encodedString = Base64.getEncoder().encodeToString(encryptedWithAES, Base64.DEFAULT);
            */
            //Encrypt AES key with RSA
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, cert.getPublicKey());
            byte[] crypteedKey = cipher.doFinal(secretKey.getEncoded());

            String cryptedkeyString = Base64.getEncoder().encodeToString(crypteedKey);

            //Ajout de la date
            Date currentDate = new Date();
            cryptedkeyString += ":"+df.format(currentDate);

            System.out.println(cryptedkeyString);

            oout.writeObject(cryptedkeyString);

            byte[] ivSpec = (byte[])iin.readObject();
            String encodedString = (String)iin.readObject();
            String signature = (String)iin.readObject();

            System.out.println(encodedString);

            boolean banswer = verify(encodedString , signature , cert.getPublicKey());
            System.out.println(banswer);
            if(!banswer){
                //TODO
            }

            String decripted = decryptData(encodedString,secretKey,new IvParameterSpec(ivSpec));
            System.out.println(decripted);

            //TODO Generate random IV
             SecureRandom random = new SecureRandom();
            byte[] ivSpec2 =  new byte[16];

            random.nextBytes(ivSpec2);
            String messageToSend = encryptData(mail+":"+hashedPWD,secretKey,new IvParameterSpec(ivSpec2));

            oout.writeObject(ivSpec2);
            oout.writeObject(messageToSend);
            //oout.flush();


            String object = (String)iin.readObject();

            System.out.println(object);
            if(object.equals(mail+" as good credentials !")){

                System.out.println("We send you a mail to email your e-mail !");


                do{
                    System.out.println("Enter secret code sends to email");
                    ansMail = sc.nextInt();
                    sc.reset();

                    //To change TODO
                    oout.writeObject(""+ansMail);


                    String[] answer = ((String)iin.readObject()).split(":");

                    String result = answer[0] ;
                    String sessionToken = answer[1] ;

                    if(result.equals("MATCH")){
                        System.out.println("MATCH");
                        System.out.println(sessionToken);

                        // HERE BEGIN WORK !
                        if(sessionToken.contains("ADMIN") || sessionToken.contains("TEACHER")) {

                            do {//Menu 1
                                System.out.println("What do you want to ?");
                                System.out.println("1. Read");
                                System.out.println("2. Write");
                                System.out.println("3. Exit");

                                int choixe = sc.nextInt();

                                switch (choixe) {
                                    case 1:
                                        System.out.println("Which student ? ");
                                        String student = sc.next();

                                        oout.writeObject(sessionToken+":READ:" + student);

                                        String reponse = (String) iin.readObject();

                                        System.out.println(reponse);
                                        break;
                                    case 2:

                                        System.out.println("Which student");
                                        String B = sc.next();

                                        System.out.println("Which course");
                                        String C = sc.next();

                                        System.out.println("Which grade");
                                        float D = sc.nextFloat();

                                        oout.writeObject(sessionToken+":WRITE" + ":" + B + ":" + C + ":" + D);

                                        String reponse2 = (String) iin.readObject();
                                        System.out.println(reponse2);

                                        break;
                                    case 3:
                                        System.exit(0);
                                        break;
                                    default:
                                        break;
                                }
                            } while (true);
                        }else if(sessionToken.contains("STUDENT")){
                            do {//Menu 2
                                System.out.println("What do you want to ?");
                                System.out.println("1. Read");
                                System.out.println("2. Exit");

                                int choixe = sc.nextInt();

                                switch (choixe) {
                                    case 1:
                                        oout.writeObject(sessionToken+":READ");
                                        String reponse = (String) iin.readObject();
                                        System.out.println(reponse);
                                        break;
                                    case 2:
                                        System.exit(0);
                                        break;
                                    default:
                                        break;
                                }
                            } while (true);
                        }

                    }else{
                        System.out.println("NOT MATCH");
                    }

                    //Récupérer la liste des élèves et l'afficher
                    //Récupérer l'élève ciblé de la base de donnée
                    //PUIS
                    //Afficher l'ensemble de ses cours avec ses points correspondants
                    //Demander quel cours il souhaite modifier
                    //Modifier dans la base de donnée et réafficher les cours changés dans la console

                }while(true);



            }else{
                System.out.println(object);
            }

            //dout.close();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (CertificateNotYetValidException e) {
            e.printStackTrace();
        } catch (CertificateExpiredException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    //Based on https://www.developpez.net/forums/d1803792/java/general-java/signature-verification-rsa-java/
    public static String sign(String plainText, PrivateKey privateKey) throws Exception {

        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }
    //Based on https://www.developpez.net/forums/d1803792/java/general-java/signature-verification-rsa-java/
    private static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }
    private String encryptData(String data , SecretKey secretKey, IvParameterSpec iv ) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipherAlpha = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipherAlpha.init(Cipher.ENCRYPT_MODE, secretKey, iv);

        byte[] encryptedWithAES = cipherAlpha.doFinal(data.getBytes());

        return Base64.getEncoder().encodeToString(encryptedWithAES);
    }
    private String decryptData(String encData ,SecretKey secretKey, IvParameterSpec iv ) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipherBeta = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipherBeta.init(Cipher.DECRYPT_MODE, secretKey ,iv);
        byte[] original = cipherBeta.doFinal(Base64.getDecoder().decode(encData));

        return new String(original);
    }
    //Method based on https://stackoverflow.com/questions/5531455/how-to-hash-some-string-with-sha256-in-java
    public static String sha256(String base) {
        try{
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(base.getBytes("UTF-8"));
            StringBuffer hexString = new StringBuffer();

            for (int i = 0; i < hash.length; i++) {
                String hex = Integer.toHexString(0xff & hash[i]);
                if(hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }

            return hexString.toString();
        } catch(Exception ex){
            throw new RuntimeException(ex);
        }
    }

    private void TestConnection(){//Test connection for know if client has internet
        final URL url;
        Scanner scBis = new Scanner(System.in);
        int ansConnect;
        int temp = 0;
        try {
            url = new URL("http://www.google.com");
            final URLConnection conn = url.openConnection();
            conn.connect();
            temp = 1;
        } catch (MalformedURLException ex) {
            Logger.getLogger(SSDProjectV1.class.getName()).log(Level.SEVERE, null, ex);
            System.out.println("Pliz check your internet connection, enter 1 to continue, or 2 to exit program");
            ansConnect = scBis.nextInt();
            switch(ansConnect){
                case 1:
                    System.out.println("You continue...");
                    break;
                case 2 :
                    System.exit(0);
                    break;
                default:
                    System.out.println("Enter a valid number pliz");
                    break;
            }
        } catch (IOException ex) {
            Logger.getLogger(SSDProjectV1.class.getName()).log(Level.SEVERE, null, ex);
            ansConnect = scBis.nextInt();
            switch(ansConnect){
                case 1:
                    System.out.println("You continue...");
                    break;
                case 2 :
                    System.exit(0);
                    break;
                default:
                    System.out.println("Enter a valid number pliz");
                    break;
            }
        }
    }
}
