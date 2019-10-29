package site

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"golang.org/x/crypto/bcrypt"
	"encoding/json"
	"time"
	"github.com/dgrijalva/jwt-go"
//	"github.com/dchest/passwordreset"

	_ "github.com/denisenkom/go-mssqldb"
)

//TODO: Change the server, port, user, password, database to your servername, port, username, password of sql server user and database name
var db *sql.DB
var server = "localhost"
var port = 1433
var user = "sa"
var password = "Worldcupt20!"
var database = "tdbei"
var jwtKey = []byte("my_secret_key_signin")
var rsetpwd_secretkey = []byte("my_secret_key_rsetpwd")

var rsetpwd_token string

// Create a struct that models the structure of a user, both in the request body, and in the DB
/*
type Credentials struct {
	Password string `json:"password", db:"password"`
	Username string `json:"username", db:"username"`
}
*/

type Signupdata struct {
	FirstName  string `json:"firstname", db:"FirstName"`
	LastName   string `json:"lastname", db:"LastName"`
/*	EmailId    string `json:"emailid", db:"EmailId"`
	Department string `json:"department, db:"Department"`
	Role       string `json:"role", db:"Role"`
*/	Username   string `json:"username", db:"Username"`
	Password   string `json:"password", db:"Password"`
	SecretAns1 string `json:"secretans1",db:"SecretAns1"`
	SecretAns2 string `json:"secretans2",db:"SecretAns2"`
}

type Signindata struct {
	Username string `json:"username", db:"Username"`
	Password string `json:"password",db:"Password"`
}

type ForgotPwddata struct {
	Username   string  `json:"username",db:"Username"`
	SecretAns1 string `json:"secretans1", db:"SecretAns1"`
	SecretAns2 string `json:"secretans2", db:"SecretAns2"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type SignupRes struct {
	Token string `json:"token"`
	Role  string `json:"role"`
}

/*---------------------------------------------------------------------------------------------
 * HTTP Route Handler Function for /Forgotpassword route which is a POST Method
 * Input : http.Request
 * Output : http.ResponseWriter
 * If the user's Username , Secretanswer1 and Secret answer2 matches, there is no output written
 * ---------------------------------------------------------------------------------------------
 */

func ForgotPasswordHandler(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type","application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers","Content-Type,access-control-allow-origin, access-control-allow-headers")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	
	/*Open the Database for fetching Employee Details to match with the request data*/
	db, err := Opendb()
	if err != nil {
		fmt.Printf("Unable to Open DB err:%v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	defer db.Close()

	var s ForgotPwddata
	json.NewDecoder(r.Body).Decode(&s)

	ctx := context.Background()
	tsql := fmt.Sprintf("SELECT Username, Password, SecretAns1, SecretAns2 FROM TEmployeeSchema.TEmployeesInfo;")

	// Execute query
	rows, err := db.QueryContext(ctx, tsql)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Printf("Unable to Query Context err:%v", err)
		return
		//return -1, err
	}

	defer rows.Close()

	// Iterate through the result set.
	for rows.Next() {
		var uname, secans1, secans2, pwd string
		//var id int

		// Get values from row.
		err := rows.Scan(&uname, &pwd, &secans1, &secans2)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Printf("Unable to Scan Row err:%v", err)
			//return -1, err
			return
		}

		if s.Username == uname && s.SecretAns1 == secans1 && s.SecretAns2 == secans2 {

			fmt.Printf("Found the user with username :%s\n",s.Username)
			
			/*if pwdval:= getPasswordHash(uname); pwdval == ""{
				w.WriteHeader(http.StatusUnauthorized)
				return
			}*/

			/*
			// Generate reset token that expires in 12 hours
			rsetpwd_token := passwordreset.NewToken(uname, 12 * time.Hour, []byte(pwd), rsetpwd_secretkey)
					// Finally, we set the client cookie for "token" as the JWT we just generated
			// we also set an expiry time which is the same as the token itself
			http.SetCookie(w, &http.Cookie{
				Name:    "token",
				Value:   rsetpwd_token,
				Expires: expirationTime,
			})
		*/
			return
		}
	}
	/* IF the username and Secret Ans1 ,Ans 2 dont match with any of the user send Unauthorized Error*/
	w.WriteHeader(http.StatusUnauthorized)
}

/*
func getPasswordHash(login string) ([] byte) {
	// return password hash for the login,
	// or an error if there's no such user

	ctx := context.Background()
	tsql := fmt.Sprintf("SELECT Username, Password FROM TEmployeeSchema.TEmployeesInfo;")

	// Execute query
	rows, err := db.QueryContext(ctx, tsql)
	if err != nil {
		//w.WriteHeader(http.StatusBadRequest)
		fmt.Printf("Unable to Query Context err:%v", err)
		return ""
		//return -1, err
	}

	defer rows.Close()

	for rows.Next() {
		var uname string
		var pwd []byte
		//var id int

		// Get values from row.
		err := rows.Scan(&uname, &pwd)
		if err != nil {
			fmt.Printf("Unable to Scan Row err:%v", err)
			//return -1, err
			return ""
		}
		if login == uname {
			fmt.Printf("Found the User:%s, Returning his Hashed Password\n", uname)
			return pwd
		}
	}
	return ""
}
*/


/*-----------------------------------------------------------------------------
 * HTTP Route Handler Function for /signup route which is a POST Method
 * Input : http.Request
 * Output : http.ResponseWriter
 * If there is no error Signing up a user , there is no output written
 * ----------------------------------------------------------------------------
 */
func SignupHandler(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type","application/json")
	//w.Header().Set("Content-Type","application/octet-stream")

	/*Open the Database for fetching Employee Details to match with the request data*/
	db, err := Opendb()
	if err != nil {
		fmt.Printf("Unable to Open DB err:%v", err)
		NewHTTPError(w,err, 500, "DB Error : Unable to Open DB.")
		return
	}

	defer db.Close()

	var s Signupdata
	json.NewDecoder(r.Body).Decode(&s)

	fmt.Printf("Received Signup request for user s.username:%s, s.password:%s, FirstName:%s, LastName:%s\n", s.Username, s.Password, s.FirstName, s.LastName)
/*
	ctx := context.Background()

	// Check if database is alive.
	err = db.PingContext(ctx)
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		fmt.Printf("Unable to Ping DB err:%v", err)
		return
		//return -1, err
	}

*/
	ctx := context.Background()
	tsql := fmt.Sprintf("SELECT FirstName, LastName, Username, Role FROM TEmployeeSchema.TEmployeesInfo WHERE Password IS NULL;")

	// Execute query
	rows, err := db.QueryContext(ctx, tsql)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Printf("Unable to Query Context err:%v", err)
		//body := NewHTTPError(w, err, 500, "DB Error : Unable to Query DB.")
		NewHTTPError(w,err, 500, "DB Error : Unable to Query DB.")
		return
	}

	defer rows.Close()

	var count int

	// Iterate through the result set.
	for rows.Next() {
		var firstname, lastname, uname, role string
		//var id int

		// Get values from row.
		err := rows.Scan(&firstname, &lastname, &uname, &role)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Printf("Unable to Scan Row err:%v", err)
			NewHTTPError(w, err, 500, "DB Error : Unable to Scan DB.")
			//w.WriteHeader(500)
			//w.Write(body)
			//return -1, err
			return
		}

		if s.FirstName == firstname && s.LastName == lastname && s.Username == uname{

			fmt.Println("User Found in Db, add password to Database")

			// Salt and hash the password using the bcrypt algorithm
	        // The second argument is the cost of hashing, which we arbitrarily set as 8 (this value can be more or less, depending on the computing power you wish to utilize)
			 hashedPassword, err := bcrypt.GenerateFromPassword([]byte(s.Password), 8)

			 fmt.Printf("Hashed password is %s\n",hashedPassword)

			//TODO: Change the TEmployeeSchema.TEmployeesInfo to your Schema and Table Name
			 tsql := fmt.Sprintf("UPDATE TEmployeeSchema.TEmployeesInfo SET Password = @Password ,SecretAns1 = @SecretAns1 , SecretAns2 = @SecretAns2 WHERE Username = @Username")

			 // Execute non-query with named parameters
			 result, err := db.ExecContext(
				 ctx,
				 tsql,
				 sql.Named("Password", string(hashedPassword)),
				 sql.Named("SecretAns1",s.SecretAns1),
				 sql.Named("SecretAns2",s.SecretAns2),
				 sql.Named("Username", uname))

			 if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Printf("Unable to Insert Password err:%v", err)
				//NewHTTPError(err, 400, "Bad request : invalid JSON.")
				//body := NewHTTPError(w, err, 500, "DB Error : Unable to Execute SQL command on DB.")
				NewHTTPError(w, err, 500, "DB Error : Unable to Execute SQL command on DB.")
				//w.WriteHeader(500)
				//w.Write(body)
				return
				 //return -1, err
			 }
			 var nre int64 // variable to store nbr of rows effected
			 var er2 error // variable to store error of RowsAffected

			 nre, er2 = result.RowsAffected()
		 
			 fmt.Printf("Updated %d row(s) with %v error, succesfully\n",nre, er2)


			/*
			// Next, insert the username, along with the hashed password into the database
	        if _, err = db.Query("insert into users values ($1, $2)", s.Username, string(hashedPassword)); err != nil {
		        	// If there is any issue with inserting into the database, return a 500 error
		    		w.WriteHeader(http.StatusInternalServerError)
					return
			}*/
			//break
			if err2 := setsignincookie(w,s.Username,role); err2 != nil {
				//NewHTTPError(err, 400, "Bad request : invalid JSON.")
				//body := NewHTTPError(w, err, 500, "Cookie Error : Unable to Set Cookie.")
				NewHTTPError(w, err, 500, "Cookie Error : Unable to Set Cookie.")
				//w.WriteHeader(500)
				//w.Write(body)
				fmt.Printf("Couldnt create SigninCookie err:%v", err2)
				return
			}
			return
		}

		fmt.Printf("Firstname: %s, Lastname: %s, Username: %s\n", firstname, lastname, uname)
		count++

	}
	NewHTTPError(w, err, 400, fmt.Sprintf("Bad Request : Unable to Find User %s or is Already Signedup.",s.FirstName))
	fmt.Printf("User:%s is Either already Signedup or Not an Authorized User\n",s.FirstName)
	return
}

/*-----------------------------------------------------------------------------
 * HTTP Route Handler Function for /signin route which is a POST Method
 * Input : http.Request
 * Output : http.ResponseWriter, a token is sent to front end
 * If there is no error Signing in a user , there is no output written
 * ----------------------------------------------------------------------------
 */
func SigninHandler(w http.ResponseWriter, r *http.Request) {

	fmt.Printf("Reached SigninHandler for r.method %v\n",r.Method)
	w.Header().Set("Content-Type","application/json")

	var s Signindata

	ctx := context.Background()

	/*Open the Database for fetching Employee Details to match with the request data*/
	db, err := Opendb()
	if err != nil {
		fmt.Printf("Unable to Open DB err:%v", err)
		//w.WriteHeader(http.StatusBadRequest)
		NewHTTPError(w,err, 500, "DB Error : Unable to Open DB.")
		return
	}

	defer db.Close()

	//Decode the data sent in signin request 
	if err = json.NewDecoder(r.Body).Decode(&s); err != nil {
		//w.WriteHeader(http.StatusBadRequest)
		NewHTTPError(w,err, 500, "json Error : Unable to Decode Request.")
		return
	}

	tsql := fmt.Sprintf("SELECT Username, Password,Role FROM TEmployeeSchema.TEmployeesInfo WHERE Password IS NOT NULL")

	// Execute query
	rows, err := db.QueryContext(ctx, tsql)
	if err != nil {
		NewHTTPError(w,err, 500, "DB Error : Unable to Query DB.")
		fmt.Printf("Unable to find user err:%v", err)
		return
		//return -1, err
	}

	defer rows.Close()

	for rows.Next() {
		var uname,storedpwd, role string

		// Get values from row.
		err := rows.Scan(&uname, &storedpwd, &role)
		if err != nil {
			NewHTTPError(w, err, 500, "DB Error : Unable to Scan DB.")
			fmt.Printf("Could Scan rows err:%v\n", err)
			return
		}

		// Compare the stored hashed password, with the hashed version of the password that was received
		if err = bcrypt.CompareHashAndPassword([]byte(storedpwd), []byte(s.Password)); err == nil {
			// If the two passwords match, break and return
			fmt.Printf("Password  matched for user:%s stored pwd :%s,User entered:%s\n",uname,storedpwd,s.Password)

			if err2 := setsignincookie(w,s.Username, role); err2 != nil {
				w.WriteHeader(http.StatusInternalServerError)
				//NewHTTPError(err, 400, "Bad request : invalid JSON.")
				fmt.Printf("Couldnt create SigninCookie err:%v", err2)
				return
			}
			fmt.Printf("User :%s Logged in\n",s.Username)
			return
		}

		fmt.Printf(" Searching Username: %s, password:%s\n", uname, storedpwd)
	}

	/*if err3 := rows.Scan(&storedpwd); err3 !=nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Printf("Unable to retrieve stored password err:%v", err)
		return
	}
	*/
	NewHTTPError(w, err, 400, fmt.Sprintf("Bad Request : Unable to Find User %s.",s.Username))
	fmt.Printf("User:%s Not an Authorized User\n",s.Username)
return 
}

/*-----------------------------------------------------------------------------
 * This function is for setting a Cookie at the client side when the user logs in
 * Input : Username of the User
 * Output : http.ResponseWriter
 * If there is no error this function would return NIL
 * ----------------------------------------------------------------------------
 */
func setsignincookie(w http.ResponseWriter, uname string, role string) error {
	
	// Declare the expiration time of the token
	// here, we have kept it as 5 minutes
	expirationTime := time.Now().Add(5 * time.Minute)
	tn := SignupRes{}
	// Create the JWT claims, which includes the username and expiry time
	claims := &Claims{
		Username: uname,
		StandardClaims: jwt.StandardClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Create the JWT string
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		// If there is an error in creating the JWT return an internal server error
		return err
	}
	tn.Token = tokenString
	tn.Role = role

	//w.Write([]byte(tokenString))
	fmt.Printf("New Token :%s encoded for user:%s, role:%v\n", tn.Token, uname, role)
	json.NewEncoder(w).Encode(tn)
	// Finally, we set the client cookie for "token" as the JWT we just generated
	// we also set an expiry time which is the same as the token itself
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
	return nil
}
/*-----------------------------------------------------------------------------
 * JWT Token Validation Function
 * Input : ResponseWriter interface and http Request pointer
 * Output : Validates JWT Token stored inthe cookie of the Request
 * ----------------------------------------------------------------------------
 */
/*
func ValidateUserJwtToken(w http.ResponseWriter, r *http.Request) {
	// We can obtain the session token from the requests cookies, which come with every request
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			// If the cookie is not set, return an unauthorized status
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// For any other type of error, return a bad request status
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Get the JWT string from the cookie
	tknStr := c.Value

	// Initialize a new instance of `Claims`
	claims := &Claims{}

	// Parse the JWT string and store the result in `claims`.
	// Note that we are passing the key in this method as well. This method will return an error
	// if the token is invalid (if it has expired according to the expiry time we set on sign in),
	// or if the signature does not match
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Finally, return the welcome message to the user, along with their
	// username given in the token
	//w.Write([]byte(fmt.Sprintf("Welcome %s!", claims.Username)))
}
*/

/*-----------------------------------------------------------------------------
 * API function to open Database.Here we are using Microsoft SQL SERVER Database
 * Input : None
 * Output : pointer to Data base and error variable
 * If there is no error opening the databse err would be set to nil
 * ----------------------------------------------------------------------------
 */
func Opendb() (db *sql.DB, err error) {

	connString := fmt.Sprintf("server=%s;user id=%s;password=%s;port=%d;database=%s;",
		server, user, password, port, database)

	// Create connection pool
	db, err = sql.Open("sqlserver", connString)
	if err != nil {
		log.Fatal("Error creating connection pool: ", err.Error())
		return
	}

	ctx := context.Background()
	err = db.PingContext(ctx)
	if err != nil {
		log.Fatal(err.Error())
		return
	}
	fmt.Printf("Connected to MSSQL server!\n")
	return
}
