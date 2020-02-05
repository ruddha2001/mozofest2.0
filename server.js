require("dotenv").config();

const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const path = require("path");
const bcrypt = require("bcrypt");
const MongoClient = require("mongodb").MongoClient;
const jwt = require("jsonwebtoken");

const app = express();

const client = new MongoClient(process.env.MONGOURL, {
  useUnifiedTopology: true
});

client.connect(function(err) {
  console.log("Connected successfully to MongoDB");
});

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.post("/register", function(req, res) {
  let name = req.body.name;
  let email = req.body.email;
  let password = req.body.password;
  let collection = client.db("mozoBase").collection("users");
  bcrypt.hash(password, 14, function(err, hash) {
    if (err) {
      console.log(err);
      res.sendStatus(500);
    } else {
      collection.find({ email: email }).toArray(function(err, result) {
        if (err) {
          console.log(err);
          res.sendStatus(500);
        }
        else if (result.length != 0) {
          console.log("Exisitng Email");
          res.sendStatus(409);
        } else {
          collection.insertOne(
            {
              name: name,
              email: email,
              password: hash
            },
            function(err, result) {
              if (err) {
                console.log(err);
                res.sendStatus(500);
              }
              res.send("Success");
            }
          );
        }
      });
    }
  });
});

app.post("/login", function(req, res) {
  let email = req.body.email;
  let password = req.body.password;
  let collection = client.db("mozoBase").collection("users");
  collection.findOne({ email: email }, function(err, result) {
    if (err) {
      console.log(res);
      res.sendStatus(401);
    } else {
      bcrypt.compare(password, result["password"], function(err, response) {
        if (err || response == false) {
          console.log("Error in authenticiation");
          res.sendStatus(401);
        } else {
          let token = jwt.sign({ user: result["name"] }, process.env.SECRET, {
            expiresIn: "1h",
            issuer: "srmkzilla.net"
          });
          res.send(token);
        }
      });
    }
  });
});

app.listen(8080, function(err) {
  if (err) console.log(err);
  else console.log("Server started on Port 8080");
});
