const express = require("express");
const mongodb = require("mongodb");
const cors = require("cors");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors());
dotenv.config();

const mongoClient = mongodb.MongoClient;
const objectId = mongodb.ObjectID;
const port = process.env.PORT || 3000;
const dbUrl = process.env.DB_URL || "mongodb://127.0.0.1:27017";
const saltRounds = 10;

// Nodemailer email authentication
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL,
    pass: process.env.PASSWORD,
  },
});

// Details of data to be sent in verification email
const mailData = {
  from: process.env.EMAIL,
  subject: "Reset your password",
};

// Details of data to be sent in verification email
const mailDataActivate = {
  from: process.env.EMAIL,
  subject: "Activate your account",
};

// Message to be sent in the verification email
let mailMessage = (url) => {
  return `<p>Hi there,<br> You have been requested to reset your password.<br>please click on the link below to reset the password.<br><a href='${url}' target='_blank'>${url}</a><br>Thank you...</p>`;
};

// Message to be sent in the verification email while registration
let mailMessageActivate = (url) => {
  return `<p>Hi there,<br> You have been registered in our website.<br>please click on the link below to activate your account.<br><a href='${url}' target='_blank'>${url}</a><br />If not registered by you do not click this link.<br>Thank you...</p>`;
};

// Middleware for token validation
function tokenValidation(req, res, next) {
  if (req.headers.authorization != undefined){
  jwt.verify(req.headers.authorization, process.env.JWT_SECRET_KEY, (err, decode) => {
      if (decode){
        req.body.id = decode.data;
        next();
      }else{
        res.send("invalid token")
      }
    })
  }else{
    res.send("no token")
  }
}

// This end-point helps to create new user
app.post("/register-user", async (req, res) => {
  try {
    let client = await mongoClient.connect(dbUrl);
    let db = client.db("url_shortener_db");
    let user = await db.collection("users").findOne({ email: req.body.email });
    let random_string = Math.random().toString(36).substring(5).toUpperCase();
    if (!user) {
      let salt = await bcrypt.genSalt(saltRounds);
      let hash = await bcrypt.hash(req.body.password, salt);
      let as = await bcrypt.hash(random_string, salt);
      req.body.password = hash;
      req.body.activate_string = as;
      req.body.urls = [];
      req.body.isActive = false;
      await db.collection("users").insertOne(req.body);
      let regUser = await db.collection("users").findOne({ email: req.body.email });
      let usrActivateUrl = `${process.env.PWDREGURL}?id=${regUser._id}&usa=${req.body.activate_string}`;
      mailDataActivate.to = req.body.email;
      mailDataActivate.html = mailMessageActivate(usrActivateUrl);
      await transporter.sendMail(mailDataActivate);
      res.status(200).json({ message: "activation link sent to mail" });
    } else {
      res.status(400).json({ message: "user already exists, please login" });
    }
    client.close();
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

// This end-point helps to login the existing user
app.post("/login", async (req, res) => {
  try {
    console.log(req.body.isValidated)
    let client = await mongoClient.connect(dbUrl);
    let db = client.db("url_shortener_db");
    let user = await db.collection("users").findOne({ email: req.body.email });
    if (user) {
      if (user.isActive){
        let token = await jwt.sign({
          data: user._id
        }, process.env.JWT_SECRET_KEY, { expiresIn: '1h' })
        console.log(token);
        let compare = await bcrypt.compare(req.body.password, user.password);
        if (compare) {
          res.status(200).json({ message: "user logged in successfully", token });
        } else {
          res.status(401).json({ message: "incorrect password" });
        }
      }else{
        res.status(403).json({message: "user is not activated. check your mail for more information"});
      }
    } else {
      res.status(400).json({ message: "user not found" });
    }
    client.close();
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

// This end-point helps the user to generate verification mail to reset the password
app.post("/forgot-password", async (req, res) => {
  try {
    let client = await mongoClient.connect(dbUrl);
    let db = client.db("url_shortener_db");
    let random_string = Math.random().toString(36).substring(5).toUpperCase();
    let user = await db.collection("users").findOne({ email: req.body.email });
    if (user) {
      let salt = await bcrypt.genSalt(saltRounds);
      let hash = await bcrypt.hash(random_string, salt);
      req.body.random_string = hash;
      await db
        .collection("users")
        .findOneAndUpdate(
          { email: req.body.email },
          { $set: { random_string: req.body.random_string } }
        );
      let pwResetUrl = `${process.env.PWRESETURL}?id=${user._id}&rps=${req.body.random_string}`;
      mailData.to = req.body.email;
      mailData.html = mailMessage(pwResetUrl);
      await transporter.sendMail(mailData);
      res.status(200).json({ message: "Password reset link sent to email" });
    } else {
      res.status(403).json({ message: "user is not registered" });
    }
    client.close();
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

// This end-point helps to verify the randomly generated string used for changing the password
app.post("/verify-random-string", async (req, res) => {
  try {
    let client = await mongoClient.connect(dbUrl);
    let db = client.db("url_shortener_db");
    let user = await db.collection("users").findOne({ _id: objectId(req.body._id) });
    let unicodeString = req.body.verificationString
    req.body.verificationString = decodeURIComponent(JSON.parse('"' + unicodeString.replace(/\"/g, '\\"') + '"'));
    if (user) {
      if (user.random_string == req.body.verificationString) {
        res.status(200).json({ message: "verification string valid" });
      } else {
        res.status(403).json({ message: "verification string not valid" });
      }
    } else {
      res.status(403).json({ message: "user doesn't exist" });
    }
    client.close();
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

app.post("/activate-user", async (req, res) => {
  try {
    let client = await mongoClient.connect(dbUrl);
    let db = client.db("url_shortener_db");
    let user = await db.collection("users").findOne({ _id: objectId(req.body._id) });
    let unicodeString = req.body.activationString
    req.body.activationString = decodeURIComponent(JSON.parse('"' + unicodeString.replace(/\"/g, '\\"') + '"'));
    if (user) {
      if (user.activate_string == req.body.activationString) {
        await db.collection('users').findOneAndUpdate({_id: user._id}, {$set: {activate_string: "something which is not good", isActive: true}})
        res.status(200).json({ message: "activation successfull" });
      } else {
        res.status(403).json({ message: "activation string is not valid" });
      }
    } else {
      res.status(403).json({ message: "user doesn't exist" });
    }
    client.close();
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

// This end-point helps to set a new password only if the conditions are met
app.put("/assign-password", async (req, res) => {
  try {
    let client = await mongoClient.connect(dbUrl);
    let db = client.db("url_shortener_db");
    let user = await db
      .collection("users")
      .findOne({ _id: objectId(req.body._id) });
      console.log(user)
    let unicodeString = req.body.verificationString
    req.body.verificationString = decodeURIComponent(JSON.parse('"' + unicodeString.replace(/\"/g, '\\"') + '"'));
    if (user.random_string == req.body.verificationString) {
      let salt = await bcrypt.genSalt(saltRounds);
      let hash = await bcrypt.hash(req.body.password, salt);
      req.body.password = hash;
      await db
        .collection("users")
        .findOneAndUpdate(
          { _id: objectId(req.body._id) },
          { $set: { random_string: "JustARandomStringWithoutHashing" } }
        );
      await db
        .collection("users")
        .findOneAndUpdate(
          { _id: objectId(req.body._id) },
          { $set: { password: req.body.password } }
        );
      res.status(200).json({ message: "password changed successfully" });
    } else {
      res.status(403).json({ message: "user with the id not found" });
    }
    client.close();
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

app.post("/home", tokenValidation, async (req, res) => {
  try {
    let client = await mongoClient.connect(dbUrl);
    let db = client.db('url_shortener_db');
    let user = await db.collection('users').findOne({_id: objectId(req.body.id)}, {fields: { fname: 1, lname: 1, email: 1, urls: 1 }})
    let urls = await db.collection('urls').find({shortString: {$in: user.urls}}).toArray();
    let data = {user: user, urls: urls}
    res.status(200).json({message: "user logged in successfully", data})
  } catch (error) {
    console.log(error);
    res.sendStatus(500); 
  }
})

function addLayer(layer){
  let rst = Math.random().toString(36).substring(5)
  for(let i = 0; i < 50; i++){
    if(layer.includes(rst)){
      rst = Math.random().toString(36).substring(5)
    }else{
      return rst;
    }
  }
}

app.post("/add-url", tokenValidation, async (req, res) => {
  try {
    let client = await mongoClient.connect(dbUrl);
    let db = client.db('url_shortener_db');
    let layer = await db.collection('layers').findOne({}, {fields: {layer: 1}});
    if(!layer){
      await db.collection('layers').insertOne({layer: []});
      layer = await db.collection('layers').findOne({}, {fields: {layer: 1}});
    }
    let rst = addLayer(layer.layer)
    await db.collection('layers').findOneAndUpdate({}, {$addToSet: {layer: rst }})
    let obj = {shortString: rst, target: req.body.target, count: 0}
    await db.collection('urls').insertOne(obj);
    await db.collection('users').findOneAndUpdate({_id: objectId(req.body.id)}, {$addToSet: {urls: rst }});
    let user = await db.collection('users').findOne({_id: objectId(req.body.id)}, {fields: {urls: 1}});
    res.status(200).json({message: 'url added successfully', user})
  } catch (err) {
    console.log(err);
    res.sendStatus(500);
  }
})

app.get("/redirect/:id", async (req, res) => {
  try {
    let client = await mongoClient.connect(dbUrl);
    let db = client.db('url_shortener_db');
    let url = await db.collection('urls').findOneAndUpdate({'shortString': req.params.id}, {$inc: {count: 1}})
    res.status(200).json({message: 'redirected successful', url})
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
})

app.listen(port, () => console.log(port));