package comp3911.cwk2;

//Bare bones implementation of user class in order to implement hashing with a salt
//Some aspects which are stored in the DB are not included since they are not required for what we do
public class User {
    private String userID;
    private String password;
    private String salt;

    public String getUserID() {return userID;}
    public String getPassword() {return password;}
    public String getSalt() {return salt;}

    public void setUserID(String value) {userID = value;}
    public void setPassword(String value) {password = value;}
    public void setSalt(String value) {salt = value;}

}
