package comp3911.cwk2;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.TemplateExceptionHandler;

@SuppressWarnings("serial")
public class AppServlet extends HttpServlet {

  private static final String CONNECTION_URL = "jdbc:sqlite:db.sqlite3";
  private static final String AUTH_QUERY = "select * from user where username=? and password=?";
  private static final String SEARCH_QUERY = "select * from patient where surname='%s' collate nocase";

  //The following are added to implement hashing passwords with a salt
  private static final String UPDATE_HASHES = "update user set password=?, salt=? where id=?";
  private static final String ALL_USERS = "select * from user";
  private static final String SALT_QUERY = "select salt from user where username=?";

  private final Configuration fm = new Configuration(Configuration.VERSION_2_3_28);
  private Connection database;

  @Override
  public void init() throws ServletException {
    configureTemplateEngine();
    connectToDatabase();
  
  }

  private void configureTemplateEngine() throws ServletException {
    try {
      fm.setDirectoryForTemplateLoading(new File("./templates"));
      fm.setDefaultEncoding("UTF-8");
      fm.setTemplateExceptionHandler(TemplateExceptionHandler.HTML_DEBUG_HANDLER);
      fm.setLogTemplateExceptions(false);
      fm.setWrapUncheckedExceptions(true);
    }
    catch (IOException error) {
      throw new ServletException(error.getMessage());
    }
  }

  private void connectToDatabase() throws ServletException {
    try {
      database = DriverManager.getConnection(CONNECTION_URL);
      hashExistingPasswords(); //Added to retrospectively hash all passwords in db
    }
    catch (SQLException error) {
      throw new ServletException(error.getMessage());
    }
  }

  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
   throws ServletException, IOException {
    try {
      Template template = fm.getTemplate("login.html");
      template.process(null, response.getWriter());
      response.setContentType("text/html");
      response.setStatus(HttpServletResponse.SC_OK);
    }
    catch (TemplateException error) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
  }

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
   throws ServletException, IOException {
    // Get form parameters
    String username = request.getParameter("username");
    String password = request.getParameter("password");
    String surname = request.getParameter("surname");

    try {
      if (authenticated(username, password)) {
        // Get search results and merge with template
        Map<String, Object> model = new HashMap<>();
        model.put("records", searchResults(surname));
        Template template = fm.getTemplate("details.html");
        template.process(model, response.getWriter());
      }
      else {
        Template template = fm.getTemplate("invalid.html");
        template.process(null, response.getWriter());
      }
      response.setContentType("text/html");
      response.setStatus(HttpServletResponse.SC_OK);
    }
    catch (Exception error) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
  }

  //Added to implement hashing passwords with a salt
  //Gets the salt stored in the database for some user - used for logging in
  private String getSalt(String username) throws SQLException {
    String salt;

    try (PreparedStatement stmt = database.prepareStatement(SALT_QUERY)){
      stmt.setString(1, username);
      ResultSet results = stmt.executeQuery();
      salt = results.getString(1);
    }

    return salt;
  }

  private boolean authenticated(String username, String password) throws SQLException {

    String salt = getSalt(username);

    //Modified query to add salt to the password provided then search for the hashed version of that
    //Change required as a salted and triple hashed version of the password is now stored in the DB
    try (PreparedStatement stmt = database.prepareStatement(AUTH_QUERY)) {
      stmt.setString(1, username);
      stmt.setString(2, hashPassword(hashPassword(hashPassword(password + salt))));
      ResultSet results = stmt.executeQuery();
      return results.next();
    }
  }

  //Method added as part of implementation of hashing passwords
  //Takes a plain text string and returns string of the SHA-256 hash
  private String hashPassword(String password){

    try{
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hashBytes = digest.digest(password.getBytes(StandardCharsets.UTF_8)); //SQLITE3 uses utf-8

      StringBuilder hexString = new StringBuilder();

      //SHA-256 is usually represented as a hexadecimal string
      for (byte hashByte : hashBytes) {
        String hex = Integer.toHexString(0xff & hashByte);
        if (hex.length() == 1) hexString.append('0');
          hexString.append(hex);
      }

      System.out.println(hexString.toString());
    return hexString.toString();
    }

    catch(NoSuchAlgorithmException e){
      System.out.println(e);
      return "";
    }
    
  }

  //This method hashes any existing passwords which are still stored in plain text

  private void hashExistingPasswords() throws SQLException{

    //Get all users in the db so we can check/update their password
      //Don't use prepared statements here since non-parameterised
    List<User> users = new ArrayList<>();
    try (Statement userStmt = database.createStatement()){
      ResultSet results = userStmt.executeQuery(ALL_USERS);
      while(results.next()){
        User rec = new User();
          rec.setUserID(results.getString(1));
          rec.setPassword(results.getString(4));
          rec.setSalt(generateSalt());

          if (rec.getPassword().length() != 64){
            System.out.println("Unhashed password detected: " + rec.getPassword());
            users.add(rec);
          }
      }

      //The only users in this list are those with unhashed passwords
      //Generates a salt for the user, adds it to the db and also uses it to hash their password which is persisted
      for (User user: users){
        try (PreparedStatement passwordStmt = database.prepareStatement(UPDATE_HASHES)) {
          passwordStmt.setString(1, hashPassword(hashPassword(hashPassword(user.getPassword() + user.getSalt()))));
          passwordStmt.setString(2, user.getSalt());
          passwordStmt.setString(3, user.getUserID());

          System.out.println("Hashing password " + user.getPassword() + " to " +  hashPassword(user.getPassword()));
          passwordStmt.executeUpdate();
        }
      }
    }
  }

  //Generates a random salt to be used in hashing
  private String generateSalt(){

    //Parameters for generating salt - limits ensure we only used uppercase letters
    //SQLITE doesn't like special characters
    int leftLimit = 65; 
    int rightLimit = 90; 
    int saltLength = 64; //Advised to use salt length = hash output length

    Random random = new Random();
    StringBuilder sb = new StringBuilder(saltLength);
    for (int i = 0; i < saltLength; i++) {
        int nextChar = leftLimit + (int)(random.nextFloat() * (rightLimit - leftLimit + 1));
        sb.append((char) nextChar);
    }

    String salt = sb.toString();
    System.out.println(salt);
    return salt;
    }

  private List<Record> searchResults(String surname) throws SQLException {
    List<Record> records = new ArrayList<>();
    String query = String.format(SEARCH_QUERY, surname);
    try (Statement stmt = database.createStatement()) {
      ResultSet results = stmt.executeQuery(query);
      while (results.next()) {
        Record rec = new Record();
        rec.setSurname(results.getString(2));
        rec.setForename(results.getString(3));
        rec.setAddress(results.getString(4));
        rec.setDateOfBirth(results.getString(5));
        rec.setDoctorId(results.getString(6));
        rec.setDiagnosis(results.getString(7));
        records.add(rec);
      }
    }
    return records;
  }
}
