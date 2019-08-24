const express = require('express');
const router = express.Router();
const Joi = require('joi');
const User = require("../models/user");
const passport = require('passport');

const userSchema = Joi.object().keys({
  email: Joi.string().email().required(),
  username: Joi.string().required(),
  password: Joi.string().regex(/^[a-zA-Z0-9]{3,30}$/).required(),
  confirmationPassword: Joi.any().valid(Joi.ref('password')).required()
});

const isAuthenticated = (req,res,next) => {
  if(req.isAuthenticated()){
    return next();
  }else{
    req.flash('error',"Invalid access");
    res.redirect('/');
  }
}
const isNotAuthenticated = (req,res,next) => {
  if(req.isAuthenticated()){
    req.flash('error',"Already Loggedin");
    res.redirect('/');    
  }else{
    return next();
  }
}
router.route('/register')
  .get(isNotAuthenticated,(req, res) => {
    res.render('register');
  })
  .post(async (req,res,next) => {
    try{
        const result = Joi.validate(req.body,userSchema);
        if(result.error){
          req.flash('error',"Data is not valid, Please try again");
          res.redirect('/users/register');
          return;
        }
        //check email is existing
        const user = await User.findOne({"email":result.value.email});
        if(user){
          req.flash('error','Email is already in use.');
          res.redirect('/users/register');
          return;
        }
        // Hash the password
        const hash =  await User.hashPassword(result.value.password);
        // Save User to DB
        delete result.value.confirmationPassword;
        result.value.password = hash;        
        const newUser = await new User(result.value);
        await newUser.save();
        req.flash('success','you may now login');
        res.redirect('/users/login');
    }catch(error){
      next(error);
    }
  });

router.route('/login')
  .get(isNotAuthenticated,(req, res) => {
    res.render('login');
  })
  .post(passport.authenticate('local',{
    successRedirect:'/users/dashboard',
    failureRedirect:'/users/login',
    failureFlash:true
  }));

  router.route('/dashboard')
    .get(isAuthenticated,(req,res) => {
      res.render('dashboard',{
        username:req.user.username
      });
  });
  router.route('/logout')
    .get((req,res) => {
      req.logout();
      req.flash('success','Successfully Logged Out');
      res.redirect('/');
  });
module.exports = router;