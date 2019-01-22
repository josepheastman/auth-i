const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const KnexSessionStore = require("connect-session-knex")(session);

const server = express();

const db = require("../database/dbConfig.js");

const sessionConfig = {
  name: "pumpkin",
  secret: "dWDWJKL&@&H#HR#RJR#fd3jfj3k39*#@*$$*!@Q($($()#$(*#$83rjfefje",
  cookie: {
    maxAge: 1000 * 15,
    secure: false
  },
  httpOnly: true,
  resave: false,
  saveUninitialized: false,
  store: new KnexSessionStore({
    tablename: "sessions",
    sidfieldname: "sid",
    knex: db,
    createtable: true,
    clearInterval: 1000 * 60 * 60
  })
};

server.use(express.json());
server.use(cors());
server.use(helmet());
server.use(session(sessionConfig));
server.use('/api/restricted/*', function (req, res, next ) {
  if (req.session && req.session.user) {
    next()
  } else {
    res.status(401).json({ message: "Not authenticated" })
  }
})

server.post("/api/register", (req, res) => {
  const creds = req.body;

  const hash = bcrypt.hashSync(creds.password, 12);

  creds.password = hash;

  db("users")
    .insert(creds)
    .then(ids => {
      res.status(201).json(ids);
    })
    .catch(err => {
      res.status(500).json({
        error: "Error registering user to the database."
      });
    });
});

server.post("/api/login", (req, res) => {
  const creds = req.body;

  db("users")
    .where({ username: creds.username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(creds.password, user.password)) {
        req.session.user = user;
        res.status(200).json({ message: "Logged in" });
      } else {
        res.status(401).json({ message: "You shall not pass!" });
      }
    })
    .catch(err => {
      res.status(500).json({
        error: "Error logging user into the database."
      });
    });
});

function protected(req, res, next) {
  if (req.session && req.session.user) {
    next();
  } else {
    res.status(401).json({ message: "Not authenticated" });
  }
}

server.get("/api/users", protected, (req, res) => {
  db("users")
    .select("id", "username", "password")
    .then(users => {
      if (users) {
        res.status(200).json(users);
      } else {
        res.status(401).json({ message: "You shall not pass!" });
      }
    })
    .catch(err =>
      res
        .status(500)
        .json({ error: "User information could not be retrieved." })
    );
});

server.get("/api/logout", (req, res) => {
  if (req.session) {
    req.session.destroy(err => {
      if (err) {
        res.status(500).send("Error logging out.");
      } else {
        res.status(200).send("Logged out");
      }
    });
  } else {
    res.json({ message: "You are already logged out" });
  }
});

/////////////////////

server.get("/api/restricted/something", (req, res) => {
  db("users")
    .select("id")
    .then(users => {
      if (users) {
        res.status(200).json(users);
      } else {
        res.status(401).json({ message: "You shall not pass!" });
      }
    })
    .catch(err =>
      res
        .status(500)
        .json({ error: "User information could not be retrieved." })
    );
});

server.get("/api/restricted/other", (req, res) => {
  db("users")
    .select("username")
    .then(users => {
      if (users) {
        res.status(200).json(users);
      } else {
        res.status(401).json({ message: "You shall not pass!" });
      }
    })
    .catch(err =>
      res
        .status(500)
        .json({ error: "User information could not be retrieved." })
    );
});

server.get("/api/restricted/a", (req, res) => {
  db("users")
    .select("password")
    .then(users => {
      if (users) {
        res.status(200).json(users);
      } else {
        res.status(401).json({ message: "You shall not pass!" });
      }
    })
    .catch(err =>
      res
        .status(500)
        .json({ error: "User information could not be retrieved." })
    );
});

module.exports = server;
