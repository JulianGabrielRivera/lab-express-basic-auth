const router = require('express').Router();
const bcryptjs = require('bcryptjs');
const saltRounds = 10;
const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard.js');

const User = require('../models/User.model');
const mongoose = require('mongoose');

router.get('/signup', isLoggedOut, (req, res, next) => {
  res.render('auth/signup.hbs');
});

router.post('/signup', (req, res, next) => {
  // without trim
  // const { username, password } = req.body;

  // with trim
  const username = req.body.username.trim();
  const password = req.body.password.trim();
  if (username === '' || password === '') {
    console.log('Error - empty username or password');
    res.render('auth/signup', {
      errorMessage: ' Username or password cannot be empty',
    });
    //  stops the function and returns
    return;
  }

  // bcrypt hashing then save to database
  // bcryptjs
  //   .hash(password, 10)
  //   .then((hashedPassword) => {
  //     //  cant use shorthand this way
  //     User.create({ username, password: hashedPassword }).then((userfromDB) => {
  //       console.log('new user', userfromDB);
  //       res.redirect('signup');
  //     });
  //   })
  //   .catch((err) => {
  //     console.log(err);
  //     res.send('failure');
  //   });
  bcryptjs
    .genSalt(saltRounds)
    // attached to above promise
    .then((salt) => {
      return bcryptjs.hash(password, salt);
    })
    // attached to abbove promise
    .then((hashedPassword) => {
      return User.create({ username, password: hashedPassword });
    })
    .then((userfromDB) => {
      console.log('new user', userfromDB);
      res.redirect('signup');

      // .then((password) => {
      //   console.log(`password secured`, password);
      // });
    })
    .catch((err) => {
      console.log(err);
      next(err);
    });
  // attached to above promise
});

router.get('/login', isLoggedOut, (req, res, next) => res.render('auth/login'));

router.get('/userProfile', isLoggedIn, (req, res, next) => {
  console.log(req.session);
  res.render('users/user-profile', { userInSession: req.session.currentUser });
});

router.post('/login', isLoggedOut, (req, res, next) => {
  //  if we do post we gotta find the values in body.
  const { username, password } = req.body;
  // find user in db based on their username
  // use bcryptjs to comapre password after we find user in db

  // set user within the session if login is successful
  User.findOne({ username })
    .then((user) => {
      bcryptjs.compareSync(password, user.password);
      req.session.currentUser = user;
      res.redirect('/userProfile');
    })
    .catch((error) => next(error));
});

router.get('/main', isLoggedIn, (req, res, next) => {
  res.render('random/cat');
});

router.get('/private', isLoggedIn, (req, res, next) => {
  res.render('random/gif');
});

module.exports = router;
