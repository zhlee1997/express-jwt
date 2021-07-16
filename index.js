var express = require("express");
var jwt = require("jsonwebtoken");
var sqlite = require("sqlite3");
var crypto = require("crypto");

// not really that good as a secret key
const KEY = "m yincredibl y(!!1!11!)<'SECRET>)Key'!";

var db = new sqlite.Database("users.sqlite3");

var app = express();

app.use(express.json());

app.post("/signup", function (req, res) {
  // in a production environment you would ideally add salt and store that in the database as well
  // or even use bcrypt instead of sha256. No need for external libs with sha256 though
  var password = crypto
    .createHash("sha256")
    .update(req.body.password)
    .digest("hex");
  db.get(
    "SELECT FROM users WHERE username = ?",
    [req.body.username],
    function (err, row) {
      if (row != undefined) {
        console.error("can't create user " + req.body.username);
        res.status(409);
        res.send("An user with that username already exists");
      } else {
        console.log("Can create user " + req.body.username);
        db.run("INSERT INTO users(username, password) VALUES (?, ?)", [
          req.body.username,
          password,
        ]);
        res.status(201);
        res.send("Success");
      }
    }
  );
});

app.post("/api/mobile/login", function (req, res) {
  console.log(req.body.username + " attempted login");
  var password = crypto
    .createHash("sha256")
    .update(req.body.password)
    .digest("hex");
  db.get(
    "SELECT * FROM users WHERE (username, password) = (?, ?)",
    [req.body.username, password],
    function (err, row) {
      if (row != undefined) {
        var payload = {
          username: req.body.username,
        };

        var token = jwt.sign(payload, KEY, {
          algorithm: "HS256",
          expiresIn: "10d",
        });
        console.log("Success");
        setTimeout(() => {
          res.status(200);
          res.send({
            success: true,
            obj: { token },
            personInfo: {
              _id: "1",
              userName: "zhlee1997",
              fullName: "Lee Zonghan",
              identityNumber: "970619075581",
              passportNumber: null,
              email: "leezonghan1997@gmail.com",
              mobile: "60124389885",
              address: "253, 9, Lorong Seoul, Taman Seoul, 09000, Kulim Kedah",
              isSubscribed: false,
              numberOfUnreadMessages: "21",
              profileImage:
                "https://i.pinimg.com/474x/bc/d4/ac/bcd4ac32cc7d3f98b5e54bde37d6b09e.jpg",
            },
          });
        }, 5000);
      } else {
        console.error("Failure");
        res.status(401);
        res.send("There's no user matching that");
      }
    }
  );
});

app.post("/api/mobile/login/jwt", function (req, res) {
  console.log(req.body.jwt + " attempted post with jwt");
  var str = req.get("Authorization");
  if (str) {
    try {
      jwt.verify(str, KEY, { algorithm: "HS256" });
      console.log(str + " is the jwt");
      res.status(200);
      res.send("jwt received");
    } catch {
      res.status(401);
      res.send("Expired Token");
    }
  } else {
    res.status(401);
    res.send("No Token");
  }
});

app.post("/api/mobile/sign-out", function (req, res) {
  console.log("attempted sign out");
  res.status(200);
  res.json({
    success: true,
    results: {},
  });
});

app.post("/auth/login/refresh", function (req, res) {
  console.log(req.body.jwt + " attempted refresh");
  var payload = {
    username: req.body.jwt,
  };

  var token = jwt.sign(payload, KEY, {
    algorithm: "HS256",
    expiresIn: "10d",
  });

  res.status(200);
  res.send({ success: true, obj: { token } });
});

app.post("/auth/login/refresh", function (req, res) {
  console.log(req.body.jwt + " attempted refresh");
  var payload = {
    username: req.body.jwt,
  };

  var token = jwt.sign(payload, KEY, {
    algorithm: "HS256",
    expiresIn: "10d",
  });

  res.status(200);
  res.send({ success: true, obj: { token } });
});

app.get("/data", function (req, res) {
  var str = req.get("Authorization");
  try {
    jwt.verify(str, KEY, { algorithm: "HS256" });
    res.send("Very Secret Data");
  } catch {
    res.status(401);
    res.send("Bad Token");
  }
});

app.get("/authorize", function (req, res) {
  console.log(req.url + " attempted authorize");
  const url = "http://localhost:3001/home/";
  res.status(302);
  res.redirect(url);
});

app.get("/home", function (req, res) {
  console.log(req.url + " attempted home, add cookie");
  res
    .cookie("hello", "12312323", { maxAge: 9000, httpOnly: true })
    .sendFile("index.html", { root: __dirname });
});

let port = process.env.PORT || 3001;
app.listen(port, function () {
  return console.log(
    "Started user authentication server listening on port " + port
  );
});
