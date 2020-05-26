const LocalStrategy = require('passport-local').Strategy;
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const User = require('../models/register');


module.exports = function initialize (passport) {
// authentication function
const authenticateUser = (email,password,done)=> {
   User.findOne({
       email:email
   })
   .then(user=> {
       if(!user) {
           return done(null,false,{message:'There is no user with that email address'})
       }
    
       bcrypt.compare(password,user.password,(err,isMatch)=> {
           if(err) throw err;
           if(isMatch) {
               return done(null,user)
           }
           else {
               return done(null,false,{message:'Password incorrect'})
           }
       })
   })
    
}
    passport.use(new LocalStrategy({usernameField:'email'},
    authenticateUser));
    passport.serializeUser(function(user,done) {
        done(null,user.id);
    })
    passport.deserializeUser(function(id,done) {
        User.findById(id,function(err,user) {
            done(null,user);
        })
    })

}