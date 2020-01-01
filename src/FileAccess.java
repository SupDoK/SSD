import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class FileAccess {

    public FileAccess(){
        //createDatabase();
    }

    public String get(String studentName){
        return "get data from "+ studentName;
    }

    public String set(String teacherName , String studentName , String course , float grade){

        boolean A = fileIntegrity(course);
        boolean D = fileIntegrity(studentName);
        if(A && D){
            boolean B = fileContain(course , teacherName);
            if(B){
                boolean C = fileContain(course , studentName);
                if(C){
                    boolean E = fileContain(studentName , course);
                    if(!E){
                        boolean F = writeFile(studentName,course,grade);
                        if(F){
                            confirmFile(studentName);
                            return " GRADE WAS ENCODED SUCCESSFULLY ! ";
                        }else{
                            return " GRADE WAS NOT ENCODED ! ";
                        }
                    }else{
                        return " STUDENT ALREADY GRADED IN THIS COURSE ! ";
                    }
                }else{
                    return " STUDENT DONT ATTEND THIS COURSE ! ";
                }
            }else{
               return " TEACHER CANNOT GRADE THIS COURSE ! ";
            }
        }else{
            return " FILE INTEGRITY BROKEN ! "+course+" : "+ A + " , "+studentName+" : " + D  ;
        }
    }

    private void createDatabase(){

        File logins = new File("D:\\SSD_DATABASE\\logins");

        File math = new File("D:\\SSD_DATABASE\\math");
        File french = new File("D:\\SSD_DATABASE\\french");
        File student1 = new File("D:\\SSD_DATABASE\\student1");

        File hash = new File("D:\\SSD_DATABASE\\hash");

        try {
            logins.createNewFile();
            math.createNewFile();
            french.createNewFile();
            student1.createNewFile();
            hash.createNewFile();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private boolean fileContain(String fileName , String name){

        try {

            File file = new File("D:\\SSD_DATABASE\\"+fileName);
            BufferedReader br = new BufferedReader(new FileReader(file));

            String line;
            while ((line = br.readLine()) != null){
                if(line.contains(name))
                    return true;
            }

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return false;
    }

    private boolean writeFile(String fileName , String course , float grade){

        if(grade < 0 || grade > 20){
            return false;
        }
        BufferedWriter writer = null;
        try {
            writer = new BufferedWriter(new FileWriter("D:\\SSD_DATABASE\\"+fileName, true));
            String toAppend = "\n"+course+":"+grade;
            writer.append(toAppend);
            writer.close();
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }

    }

    // File Integrity TODO

    private boolean fileIntegrity(String fileName){

        String hash = getFileHash(fileName);

        return true;
    }

    private void confirmFile(String fileName){


    }

    private String getFileHash(String fileName){

        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");

           // byte[] hash = digest.digest(data.getBytes("UTF-8"));
            //return bytesToHex(hash);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return "";
    }
}
