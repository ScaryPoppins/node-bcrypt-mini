require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const massive = require('massive');

const app = express();

app.use(express.json());

let { SERVER_PORT, CONNECTION_STRING, SESSION_SECRET } = process.env;

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  })
);

massive(CONNECTION_STRING).then(db => {
  app.set('db', db);
  console.log(`dbworks :)`)
});



// THIS ENDPOINT HANDLES USER AUTHENTICATION FOR USERS TO SIGN UP TO THE WEBSITE.  
// ALSO SEE signup() IN APP.JS in SOURCE FOLDER

app.post('/auth/signup', async (req, res) => {
//Expect to receive email and password properties on req.body.
  let {email, password} = req.body;
//Allows 'db' to look in the db folder for a specified file
  let db = req.app.get('db')

// Checks to see if a user already exists.  
// If email already exists, the user will be notified that it already exists
  let userFound = await db.check_user_exists([email]);
  if (userFound[0]) {
    return res.status(200).send('Email already exists')
  } 
  // salt and hash shorthand using bcrypt
  let salt = bcrypt.genSaltSync(10);
  let hash = bcrypt.hashSync(password, salt);

  // create user and add to db database
  let createdUser = await db.create_customer([email, hash])
  // puts the user on a cookie session
  req.session.user = { id: createdUser[0].id, email: createdUser[0].email }
  res.status(200).send(req.session.user)
});




// THIS ENDPOINT HANDLES THE CREATE LOGIN FUNCTIONALITY
// ALSO SEE login() IN APP.JS in SOURCE FOLDER

app.post('/auth/login', async (req, res) => {
//Expect to receive email and password properties on req.body.
  let { email, password } = req.body;
//Allows 'db' to look in the db folder for a specified file.  
  let db = req.app.get('db')
// If email does not exist, inform user that it's incorrect.   
  let userFound = await db.check_user_exists(email)
  if (!userFound[0]) {
    return res.status(200).send('Incorrect email. Please try again.');
  }

// Use bcrypts compareSync method to compare the input password on req.body with the users user_password.
  let result = bcrypt.compareSync(password, userFound[0].user_password)

  //If the passwords match, then the user has successfully authenticated, put the user object on session (excluding their hashed password) and send it to the client.
  if (result) {
    req.session.user = { id: userFound[0].id, email: userFound[0].email }
    res.status(200).send(req.session.user)
  } else {
    return res.status(401).send('Incorrect email/password')
  }
})

// THIS ENDPOINT HANDLES THE LOGOUT FUNCTIONALITY
// ALSO SEE logout() IN APP.JS in SOURCE FOLDER

app.get('/auth/logout', (req, res) => {
  req.session.destroy();
  res.sendStatus(200);
});



// THIS ENDPOINT HANDLES THE VIEW FUNCTIONALITY
// One final piece of server code is needed to complete our authentication process. We need a way to check that our user is logged in and pull their information into our application if they are.
// This endpoint should:
// Check if their is a user on session.
// If there is, send it up.
// If there isn't send an error.

app.get('/auth/user', (req, res) => {
  if (req.session.user) {
    res.status(200).send(req.session.user)
  } else {
    res.status(401).send('please log in')
  }
});

app.listen(SERVER_PORT, () => {
  console.log(`Listening on port: ${SERVER_PORT}`)
});





app.listen(SERVER_PORT, () => {
  console.log(`Listening on port: ${SERVER_PORT}`);
});
