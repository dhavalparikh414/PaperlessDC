package main

import (
	"fmt"
	"log"
	"net/http"

	_ "github.com/denisenkom/go-mssqldb"
	"github.com/dhavalparikh/PaperlessDC/site"
//	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

/*
var db *sql.DB
var server = "localhost"
var port = 1433
var user = "sa"
var password = "Worldcupt20!"
var database = "<>"
*/

type MyServer struct {
    r *mux.Router
}

func main() {

	router := site.NewRouter()
	fmt.Println("Running server now...")
	http.Handle("/",&MyServer{router})
	log.Fatal(http.ListenAndServe(":8080", nil/*handlers.CORS()(router)*/))

	fmt.Println("HTTP Server Running on port 8080")

	/*connString := fmt.Sprintf("server=%s;user id=%s;password=%s;port=%d;database=%s;",
		server, user, password, port, database)


	var err error

	// Create connection pool
	db, err = sql.Open("sqlserver", connString)
	if err != nil {
		log.Fatal("Error creating connection pool: ", err.Error())
	}

	ctx := context.Background()
	err = db.PingContext(ctx)
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Printf("Connected to MSSQL server!\n")
	*/
}

func (s *MyServer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
    if origin := req.Header.Get("Origin"); origin != "" {
		rw.Header().Set("Access-Control-Allow-Origin", origin)
		rw.Header().Set("Vary",origin)
        rw.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
        rw.Header().Set("Access-Control-Allow-Headers",
            "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	}
    // Stop here if its Preflighted OPTIONS request
    if req.Method == "OPTIONS" {
		return
    }
    // Lets Gorilla work
    s.r.ServeHTTP(rw, req)
}
