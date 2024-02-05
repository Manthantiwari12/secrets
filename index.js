import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt, { hash } from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";



const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "secrets",
  password: "172005manu",
  port: 5432,
});
db.connect();

const app = express();
const port = 3000;
const saltrounds = 10;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  secret: "TOPSECRETWORD",
  resave: false,
  saveUninitialized: true,
}));

app.use(passport.initialize());
app.use(passport.session());



app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/secrets",(req,res)=>{
  console.log(req.user);
  if(req.isAuthenticated()){
    res.render("secrets.ejs");
  }else{
    res.render("login.ejs");
  }
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;
  const checkResult = await db.query("select * from users where email = $1", [email]);

  if (checkResult.rows.length > 0) {
    res.send("email already exist. try logging in.");
  } else {
    //pasword hashing
    bcrypt.hash(password, saltrounds, async (err, hash) => {
      if (err) {
        console.log("error hashin password:", err);
      } else {
        const result = await db.query(
          "insert into users(email,password) values($1,$2)",
          [email, hash]
        );
        console.log(result);
        res.render("secrets.ejs");
      }
    });

  }
});

app.post("/login", passport.authenticate("local",{
  successRedirect:"/secrets",
  failureRedirect:"/login"
}));

passport.use(new Strategy(async function verify(username,password,cb){
  try {
    const result = await db.query("select * from users where email = $1", [username]);

    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedhashedpassword = user.password;

      bcrypt.compare(password, storedhashedpassword, (err, result) => {
        if (err) {
          return cb(err);
        } else {
          if (result) {
            return cb(null,user);
          } else {
            return cb(null, false);
          }
        }
      })

    } else {
      return cb("user not found");
    }
  } catch (err) {
    return cb(err)
  }
}));

passport.serializeUser((user,cb)=>{
  cb(null,user);
});

passport.deserializeUser((user,cb)=>{
  cb(null,user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
