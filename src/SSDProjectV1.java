import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
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

        KeyPairGenerator PrivkeyGen;

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

            //MESSAGE 1
            oout.writeObject(hello+":"+sign(hello , privateKey));
            //MESSAGE 2
            oout.writeObject(publicKey);
            //oout.writeObject( sign(hello , privateKey));



            //Verify certificate !
            //MESSAGE 3
            X509Certificate cert = (X509Certificate)iin.readObject();
            if(!cert.getIssuerDN().getName().equals("EMAILADDRESS=alphatangototo789@gmail.com, CN=SSD, OU=SSD, O=Crochez ssd, L=Bruxelles, ST=Bruxelles, C=BE")){
                throw  new CertificateException();
            }
            if (cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
                cert.verify(cert.getPublicKey());
                System.out.println("Verified: " + cert.getSubjectX500Principal());
            }

            System.out.println(cert.getPublicKey());

            //MESSAGE 4
            //Get encrypted AES key
            String signedEncAESKey = (String)iin.readObject();
            String encAESKey = signedEncAESKey.split("_")[0];
            String signature = signedEncAESKey.split("_")[1];

            boolean banswer = verify(encAESKey , signature , cert.getPublicKey());
            System.out.println(banswer);
            if(!banswer){
                //TODO
            }

            //Check date
            boolean ok = checkDates(encAESKey.split(":")[1]);
            System.out.println(ok);
            if(!ok){
                //TODO
            }


            System.out.println(encAESKey.split(":")[0]);
            //Decipher AES key !
            Cipher cipher2c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher2c.init(Cipher.DECRYPT_MODE, privateKey);
            SecretKeySpec AESKey = new SecretKeySpec(cipher2c.doFinal(Base64.getDecoder().decode(encAESKey.split(":")[0])), "AES");


            //Send client secure handshake
            String messageToSend = prepareSend("Client Secure Handshake",AESKey , privateKey);
            //MESSAGE 6
            oout.writeObject(messageToSend);

            //Receive Server secure handshake
            //MESSAGE 7
            //byte[] ivSpec = (byte[])iin.readObject();
            //MESSAGE 8
            String signedEncString = (String)iin.readObject();
            String messageReceived = prepareReceive(signedEncString , AESKey , cert.getPublicKey());
            System.out.println(messageReceived);


            //Send user credentials
            String messageToSend2 = prepareSend(mail+"-"+hashedPWD,AESKey , privateKey);
            //MESSAGE 9
            oout.writeObject(messageToSend2);


            //MESSAGE 10
            String signedEncString10 = (String)iin.readObject();
            String messageReceived10 = prepareReceive(signedEncString10 , AESKey , cert.getPublicKey());

            if(messageReceived10.equals(mail+" as good credentials !")){
                System.out.println(messageReceived10);
                System.out.println("We send you a mail to email your e-mail !");


                do{
                    System.out.println("Enter secret code sends to email");
                    ansMail = sc.nextInt();
                    sc.reset();

                    //To change TODO
                    //Send user credentials
                    String messageToSend3 = prepareSend(""+ansMail,AESKey , privateKey);
                    //MESSAGE 11
                    oout.writeObject(messageToSend3);

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
                System.out.println(messageReceived10);
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

    private String prepareSend(String data, SecretKeySpec AESKey, PrivateKey privateKey) throws Exception {

        //TODO Generate random IV
        SecureRandom random = new SecureRandom();
        byte[] ivSpec0 =  new byte[16];

        random.nextBytes(ivSpec0);
        String message5 = encryptData(data,AESKey,new IvParameterSpec(ivSpec0));
        String messageToSend = Base64.getEncoder().encodeToString(ivSpec0)+":"+timeMessage(message5);

        return messageToSend+"_"+sign(messageToSend , privateKey);
    }
    private String prepareReceive(String signedEncString, SecretKeySpec AESKey, PublicKey publicKey) throws Exception {

        String encMessage = signedEncString.split("_")[0];
        String signature2 = signedEncString.split("_")[1];

        boolean banswer0 = verify(encMessage , signature2 , publicKey);
        System.out.println(banswer0);
        if(!banswer0){
            //TODO
        }

        //Check date
        boolean ok0 = checkDates(encMessage.split(":")[2]);
        System.out.println(ok0);
        if(!ok0){
            //TODO
        }

        //Decipher message
        String decryptedMessage = decryptData(encMessage.split(":")[1] , AESKey ,new IvParameterSpec(Base64.getDecoder().decode(encMessage.split(":")[0])));

        return decryptedMessage;
    }

    private boolean checkDates(String date){

        //DateFormat df = new SimpleDateFormat("yyyy-MM-dd-hh-mm-ss");

        String[] splitted = date.split("-");

        Calendar construct = Calendar.getInstance();

        construct.set(Calendar.YEAR , Integer.parseInt(splitted[0]));
        construct.set(Calendar.MONTH , Integer.parseInt(splitted[1]));
        construct.set(Calendar.DAY_OF_MONTH , Integer.parseInt(splitted[2]));

        construct.set(Calendar.HOUR , Integer.parseInt(splitted[3]));
        construct.set(Calendar.MINUTE , Integer.parseInt(splitted[4]));
        construct.set(Calendar.SECOND , Integer.parseInt(splitted[5]));

        construct.add(Calendar.SECOND, 360);
        Date toCompareplus5 = construct.getTime();
        Date currentDate = new Date();

        System.out.println(currentDate);
        System.out.println(toCompareplus5);

        if(toCompareplus5.after(currentDate)){
            //TODO
            return true;
        }

        return false;
    }

    private String timeMessage(String message){
        DateFormat df = new SimpleDateFormat("yyyy-MM-dd-hh-mm-ss");
        Date currentDate = new Date();
        return message+":"+df.format(currentDate);
    }

    //Based on https://www.developpez.net/forums/d1803792/java/general-java/signature-verification-rsa-java/
    private static String sign(String plainText, PrivateKey privateKey) throws Exception {

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
