package main

import (
	"bufio"
	"code.google.com/p/go.crypto/bcrypt"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/coopernurse/gorp"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	_ "github.com/mattn/go-sqlite3"
	"github.com/unrolled/render"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const port string = ":8001"
const dbfile string = "db_mux_sqlite.db"
const dockercmd string = "/usr/bin/docker"
const dksyncthingpath = "/home/syncthing"
const hostsyncthingpath = "/home/syncthing/real/"
const st_uid = 22000
const st_gid = 100
const originconfigxml = "/home/syncthing/config.xml"
const gnull = 0
const guser = 1
const gadmin = 100

type User struct {
	Id         int64 `db:"user_id"`
	Created    int64
	Name       string
	Password   string
	Email      string
	GuiPort    int
	ListenPort int
	HomePath   string
	Group      int
	Status     string
}

var dbmap = initDb()
var cookieHandler = securecookie.New(
	securecookie.GenerateRandomKey(64),
	securecookie.GenerateRandomKey(32))

func createUser(name, password string, email string, guiport, listenport int, homepath string, group int, status string) bool {

	if !existUserName(name) {
		hash_password := hash(password)
		user := User{
			Created:    time.Now().UnixNano(),
			Name:       name,
			Password:   hash_password,
			Email:      email,
			GuiPort:    guiport,
			ListenPort: listenport,
			HomePath:   homepath,
			Group:      group,
			Status:     status,
		}
		err := dbmap.Insert(&user)
		checkErr(err, "Insert failed")
		return true
	} else {
		log.Println("User exist!")
		return false
	}
}

func getUserId(user_id int) User {
	user := User{}
	err := dbmap.SelectOne(&user, "select * from users where user_id=?", user_id)
	checkErr(err, "SelectOne failed")
	return user
}

func getUserName(name string) User {
	user := User{}
	err := dbmap.SelectOne(&user, "select * from users where Name=?", name)
	checkErr(err, "SelectOne failed")
	return user
}

func existUserName(name string) bool {
	exist, err := dbmap.SelectInt("select count(*) from users where Name=?", name)
	checkErr(err, "Select count failed")
	return (exist == 1)
}

func CountUsers() int64 {
	count, err := dbmap.SelectInt("select count(*) from users")
	checkErr(err, "Select count failed")
	return count
}

func getUsers() []User {

	var users []User

	_, err := dbmap.Select(&users, "select * from users order by Name")
	checkErr(err, "getUsers Select failed")
	return users
}

func initDb() *gorp.DbMap {
	db, err := sql.Open("sqlite3", dbfile)
	checkErr(err, "sql.Open failed")

	dbmap := &gorp.DbMap{Db: db, Dialect: gorp.SqliteDialect{}}

	dbmap.AddTableWithName(User{}, "users").SetKeys(true, "Id")

	err = dbmap.CreateTablesIfNotExists()
	checkErr(err, "Create tables failed")

	return dbmap
}

func checkErr(err error, msg string) {
	if err != nil {
		log.Println(msg, err)
	}
}

func hash(password string) string {
	p := []byte(password)
	h, e := bcrypt.GenerateFromPassword(p, bcrypt.DefaultCost)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
	return string(h)
}
func checkHash(hash string, passwd string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(passwd))
	return err == nil
}

func main() {

	defer dbmap.Db.Close()

	router := mux.NewRouter()

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		SimplePage(w, r, "mainpage")
	})

	router.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			SimplePage(w, r, "login")
		} else if r.Method == "POST" {
			LoginPost(w, r)
		}
	})

	router.HandleFunc("/signup", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			SimplePage(w, r, "signup")
		} else if r.Method == "POST" {
			SignupPost(w, r)
		}
	})

	router.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		Logout(w, r)
	})

	router.HandleFunc("/home", func(w http.ResponseWriter, r *http.Request) {
		SimpleAuthenticatedPage(w, r, "home", guser)
	})

	router.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		SimpleAuthenticatedJSON(w, r, DockerStatus, guser)
	}).Methods("GET")

	router.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		SimpleAuthenticatedJSON(w, r, StartDocker, guser)
	}).Methods("GET")

	router.HandleFunc("/stop", func(w http.ResponseWriter, r *http.Request) {
		SimpleAuthenticatedJSON(w, r, StopDocker, guser)
	}).Methods("GET")
	/*
		router.HandleFunc("/admin/user/{name}", func(w http.ResponseWriter, r *http.Request) {
			SimpleAuthenticatedJSON(w, r, UserRead, gadmin)
		}).Methods("GET")

		router.HandleFunc("/admin/user", func(w http.ResponseWriter, r *http.Request) {
			SimpleAuthenticatedJSON(w, r, UserWrite, gadmin)
		}).Methods("POST")
	*/
	router.HandleFunc("/admin/users", func(w http.ResponseWriter, r *http.Request) {
		SimpleAuthenticatedJSON(w, r, UsersList, gadmin)
	}).Methods("GET")

	/*
		router.HandleFunc("/admin/user/{name}", func(w http.ResponseWriter, r *http.Request) {
			SimpleAuthenticatedJSON(w, r, UsersDelete, gadmin)
		}).Methods("DELETE")

		router.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
			SimpleAuthenticatedPage(w, r, "admin", gadmin)
		}).Methods("GET")

	*/

	router.Handle("/static/{rest}", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	http.ListenAndServe(port, router)

}

func SimplePage(w http.ResponseWriter, req *http.Request, template string) {

	r := render.New(render.Options{})
	r.HTML(w, http.StatusOK, template, nil)

}

func SimpleAuthenticatedPage(w http.ResponseWriter, req *http.Request, template string, group int) {

	user, _, grp := GetSessionUserName(req)

	if user == "" || group > grp {
		http.Redirect(w, req, "/login", 301)
	}

	r := render.New(render.Options{})
	r.HTML(w, http.StatusOK, template, nil)

}

func SimpleAuthenticatedJSON(w http.ResponseWriter, req *http.Request, f func(http.ResponseWriter, *http.Request) []byte, group int) {

	user, _, grp := GetSessionUserName(req)
	r := render.New(render.Options{})

	if user == "" || group > grp {
		r.JSON(w, http.StatusUnauthorized, map[string]string{"result": "Unauthorized User"})
	} else {
		var dat interface{}
		j := f(w, req)
		if err := json.Unmarshal(j, &dat); err != nil {
			panic(err)
		}
		r.JSON(w, http.StatusOK, dat)
	}
}

/* Login */
func LoginPost(w http.ResponseWriter, req *http.Request) {

	username := req.FormValue("inputUsername")
	password := req.FormValue("inputPassword")

	user := getUserName(username)

	if checkHash(user.Password, password) && user.Status != "blocked" {
		SetSession(username, password, user.Group, w)
		http.Redirect(w, req, "/home", 302)
	} else {
		http.Redirect(w, req, "/login", 301)
	}
}

func SignupPost(w http.ResponseWriter, req *http.Request) {

	username := req.FormValue("inputUsername")
	password := req.FormValue("inputPassword")
	confirm_password := req.FormValue("inputConfirmPassword")
	email := req.FormValue("inputEmail")

	if password != confirm_password {
		http.Redirect(w, req, "/singup", 302)
	}
	group := guser
	status := "blocked"

	if CountUsers() == 0 {
		group = gadmin
		status = ""
	}
	if createUser(username, password, email, GetPort(), GetPort(), hostsyncthingpath+username, group, status) {
		log.Print("Problem create User")
	}

	http.Redirect(w, req, "/login", 302)

}

func Logout(w http.ResponseWriter, req *http.Request) {

	ClearSession(w)
	http.Redirect(w, req, "/", 302)

}

/* Session */
func GetSessionUserName(request *http.Request) (username string, password string, group int) {
	username = ""
	password = ""
	group = gnull

	if cookie, err := request.Cookie("session"); err == nil {
		cookieValue := make(map[string]string)
		if err = cookieHandler.Decode("session", cookie.Value, &cookieValue); err == nil {
			username = cookieValue["name"]
			password = cookieValue["password"]
			group, _ = strconv.Atoi(cookieValue["group"])
		}
	}
	return username, password, group
}

func SetSession(userName string, password string, group int, response http.ResponseWriter) {
	value := map[string]string{
		"name":     userName,
		"password": password,
		"group":    strconv.Itoa(group),
	}
	if encoded, err := cookieHandler.Encode("session", value); err == nil {
		cookie := &http.Cookie{
			Name:  "session",
			Value: encoded,
			Path:  "/",
		}
		http.SetCookie(response, cookie)
	}
}

func ClearSession(response http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(response, cookie)
}

/* Admin */
func UsersList(w http.ResponseWriter, req *http.Request) []byte {
	ret, _ := json.Marshal(getUsers())
	log.Printf(string(ret))
	return []byte(`{"result": "OK"}`)
}

/* Docker */
func DockerStatus(w http.ResponseWriter, req *http.Request) []byte {

	username, _, _ := GetSessionUserName(req)
	user := getUserName(username)

	guiport := strconv.Itoa(user.GuiPort)
	listenport := strconv.Itoa(user.ListenPort)

	if user.Id == 0 {
		// User doesn't exist!
		return []byte(`{"result": "Error this id does not exist."}`)
	}
	if IsDockerRunning(user.Name) {
		return []byte(`{"result": "Running", "username": "` + user.Name + `", "guiport": "` + guiport + `", "listenport": "` + listenport + `"}`)
	} else {
		return []byte(`{"result": "Not running", "username": "` + user.Name + `", "guiport": "` + guiport + `", "listenport": "` + listenport + `"}`)
	}
}
func IsDockerRunning(name string) bool {
	dockerParameters := []string{"ps", "-q", "-f", "status=running", "-f", "name=" + name}
	out := runDocker(dockerParameters)
	return (string(out) != "")
}

func IsDockerExist(name string) bool {
	dockerParameters := []string{"ps", "-a", "-q", "-f", "name=" + name}
	out := runDocker(dockerParameters)
	return (string(out) != "")
}
func RemoveDocker(w http.ResponseWriter, req *http.Request) []byte {
	username, _, _ := GetSessionUserName(req)
	user := getUserName(username)

	if IsDockerRunning(user.Name) {
		return []byte(`{"result": "This docker is running, stop it before remove"}`)
	}
	dockerParameters := []string{"rm", user.Name}
	runDocker(dockerParameters)
	return []byte(`{"result": "OK"}`)
}

func (user *User) PrepareDocker() bool {

	// Mkdir user.HomePath
	os.Mkdir(user.HomePath, 0750)
	// Chown syncthing:users
	os.Chown(user.HomePath, st_uid, st_gid)
	// ReplaceConfigXML user.HomePath/config.xml user.Name
	ReplaceConfigXML(originconfigxml, user.HomePath+"/config.xml", user.Name, user.Password, strconv.Itoa(user.GuiPort), strconv.Itoa(user.ListenPort))
	// Chown file
	os.Chown(user.HomePath+"/config.xml", st_uid, st_gid)
	return true
}
func (user *User) CleanDocker() bool {
	// Remove user.HomePath
	return true
}

func StartDocker(w http.ResponseWriter, req *http.Request) []byte {

	username, _, _ := GetSessionUserName(req)
	user := getUserName(username)

	var dockerParameters []string

	if IsDockerRunning(user.Name) {
		return []byte(`{"result": "This docker is running, yet!"}`)
	}
	if IsDockerExist(user.Name) {
		// Docker exist, but not running
		dockerParameters = append(dockerParameters, "start", user.Name)
	}
	if _, err := os.Stat(user.HomePath + "/config.xml"); err != nil {
		// Config doesn't exist, PrepareDocker
		user.PrepareDocker()
		strGP := strconv.Itoa(user.GuiPort)
		strLP := strconv.Itoa(user.ListenPort)
		dockerParameters = append(dockerParameters, "run", "-d", "--net=host", "-v", user.HomePath+":"+dksyncthingpath, "-p", strGP+":"+strGP, "-p", strLP+":"+strLP, "--name", user.Name, "syncthing")
	}

	out := runDocker(dockerParameters)
	return []byte(`{"id": "` + string(out) + `"}`)

}

func StopDocker(w http.ResponseWriter, req *http.Request) []byte {

	username, _, _ := GetSessionUserName(req)
	user := getUserName(username)

	dockerParameters := []string{"stop", user.Name}
	out := runDocker(dockerParameters)
	return []byte(`{"result": "` + string(out) + `"}`)

}

func runDocker(parameters []string) []byte {
	fmt.Printf(dockercmd, parameters)
	fmt.Println("")
	out, err := exec.Command(dockercmd, parameters...).Output()
	if err != nil {
		fmt.Println("error occured")
		fmt.Printf("%s", err)
	}
	return out
}
func GetPort() int {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func writeLines(lines []string, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}
func ReplaceConfigXML(origin, definitive, name, passwd, guiport, listenport string) {
	lines, err := readLines(origin)
	if err != nil {
		fmt.Println("Error!")
	}
	for i := range lines {
		lines[i] = strings.Replace(lines[i], "{USER}", name, -1)
		lines[i] = strings.Replace(lines[i], "{PASSWORD}", passwd, -1)
		lines[i] = strings.Replace(lines[i], "{GUI_PORT}", guiport, -1)
		lines[i] = strings.Replace(lines[i], "{LISTEN_PORT}", listenport, -1)
	}

	if err := writeLines(lines, definitive); err != nil {
		fmt.Println("Error!")
	}
	return
}
