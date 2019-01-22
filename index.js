const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");

const db = require("./database/dbConfig.js");

const server = express();

server.use(express.json());
server.use(cors());
server.use(helmet());

server.post("/api/login", (req, res) => {
  const creds = req.body;

  db("users")
    .where({ username: creds.username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(creds.password, user.password)) {
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

server.post("/api/register", (req, res) => {
  const creds = req.body;

  const hash = bcrypt.hashSync(creds.password, 8);

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

server.get("/api/users", (req, res) => {
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

server.listen(5000, () => console.log("\nrunning on port 5000\n"));
