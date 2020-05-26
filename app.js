const express =require('express');
const bcrypt = require('bcrypt');
const User = require('./models/register')
const mongoose = require('mongoose');
const passport = require('passport');
const flash = require('express-flash');
const session = require('express-session');
const uuid  = require('uuid');
const initlizeuser = require('./passport-config/passport-auth');
const app =express();
const errors=[]
app.set('view-engine','ejs');
app.use(express.urlencoded({extended:false}))
app.use(flash())
app.use(session({
    secret:uuid.v4(),
    resave:false,
    saveUninitialized:false
}));
app.use(passport.initialize());
app.use(passport.session());
initlizeuser(passport);

mongoose.connect('mongodb://localhost/trial',{ useNewUrlParser: true }, ()=> {
    console.log('Successifully connected to mongo database')
});
app.get('/',checkauth,(req,res)=> {
    res.render('index.ejs',{name:req.user.name});
});

app.get('/login',checkNotauth,(req,res)=> {
    res.render('login.ejs')
})

app.post('/login',checkNotauth,passport.authenticate('local',{
    successRedirect:'/',
    failureRedirect:'/login',
    failureFlash:true
}));

app.get('/register',checkNotauth,(req,res)=> {
    res.render('register.ejs')
})

app.post('/register',checkNotauth,(req,res)=>{
  let {name,email,password}=req.body;
  if(!name || !email) {
    errors.push({err:'Please fill in all forms'})
  }

  if(password.length < 6) {
      errors.push({err:'Password must at least be six characters'})
  }

  if(errors > 1 ) {
      res.render('register.ejs',{
          name,
          email,
          password,
          errors
      })
  }
  else {
    const newUser = new User({
        name,
        email,
        password
    })
    // encryption
    bcrypt.genSalt(10,(err,salt)=> {
        bcrypt.hash(newUser.password,salt,(err,hash)=> {
            if(err) throw err;
            newUser.password=hash;
            newUser.save()
            .then(
                res.redirect('/login'),
                console.log('Successfully created an account loser')
            )
        })
    })
  }
  
})

app.get('/logout',(req,res)=>{
  req.logOut();
  res.redirect('/login')
});

function checkauth(req,res,next) {
    if(req.isAuthenticated()) {
        return next();
    }

    res.redirect('/login')
}

function checkNotauth(req,res,next) {
    if(req.isAuthenticated()) {
       return res.redirect('/');
    }

    next();
}

const PORT = process.env.PORT || 3000;
app.listen(PORT ,()=> {
    console.log(`server started on port ${PORT}`)
});