import java.util.Date;

public class TimedObject {

    private Date date;
    private Object object;

    public TimedObject (Date date , Object object){
        this.date = date;
        this.object = object;
    }

    public Date getDate(){
        return date;
    }
    public Object getObject(){
        return object;
    }
}
