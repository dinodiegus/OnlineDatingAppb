const express = require('express');
const exphbs = require('express-handlebars');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const passport = require('passport');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const flash = require('connect-flash');
const bcrypt = require('bcryptjs');
const formidable = require('formidable');
const Handlebars = require('handlebars');
const { allowInsecurePrototypeAccess} = require('@handlebars/allow-prototype-access');

// Load models
const Message = require('./models/message');
const User = require('./models/user');
const Chat = require('./models/chat');
const app = express();

// load keys file
const Keys = require('./config/keys');

//Load Helpers
const {requireLogin,ensureGuest} = require('./helpers/auth');
const {uploadImage} = require('./helpers/aws');
const {getLastMoment} = require('./helpers/moment');

// use body parser middleware
app.use(bodyParser.urlencoded({extended:false}));
app.use(bodyParser.json());

// configuration for authentication
app.use(cookieParser());
app.use(session({
    secret: 'mysecret',
    resave: true,
    saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());
app.use((req,res,next) =>{
    res.locals.success_msg = req.flash('success_msg');
    res.locals.error_msg = req.flash('error_msg');
    res.locals.error = req.flash('error');
    next();
});

// *video40* Setup express static folder to serve js, css files
app.use(express.static('public'));

//Make user global object
app.use((req,res, next) => {
    res.locals.user = req.user || null;
    next();
});

// Load Facebook strategy
require('./passport/facebook');
require('./passport/google');
require('./passport/local');

// connect to MongoDB
mongoose.connect(Keys.MongoDB, { useNewUrlParser:true, useUnifiedTopology: true }).then(() => {
    console.log('Server is connected do MongoDB');
}).catch((err) => {
    console.log(err);
});

// environment variable for port
const port = process.env.PORT || 3000;

// setup view engine
app.engine('handlebars', exphbs({defaultLayout:'main',
handlebars: allowInsecurePrototypeAccess(Handlebars),
    helpers: {
        getLastMoment:getLastMoment
    }
}));
app.set('view engine','handlebars');

app.get('/',ensureGuest,(req,res) => {
    res.render('home',{
        title: 'Home'
    });
});

app.get('/about',ensureGuest,(req,res) => {
    res.render('about', {
        title: 'About'
    });
});

app.get('/contact',ensureGuest,(req,res) => {
    res.render('contact',{
        title: 'Contact'
    });
});

app.get('/auth/facebook/',passport.authenticate('facebook',{
    scope: ['email']
}));
app.get('/auth/facebook/callback',passport.authenticate('facebook',{
    successRedirect: '/profile',
    failureRedirect: '/'
}));
app.get('/auth/google',passport.authenticate('google',{
    scope: ['profile']
}));
app.get('/auth/google/callback',passport.authenticate('google',{
    successRedirect: '/profile',
    failureRedirect: '/'
}));
app.get('/profile',requireLogin,(req,res) => {
    User.findById({_id:req.user._id}).then((user) =>{
        if (user) {
           user.online = true;
           user.save((err,user) => {
               if(err){
                   throw err;
               }else{
                    res.render('profile',{
                        title: 'Profile',
                        user:user 
                 });
               }

           }) 
        }
    });
});
app.post('/updateProfile',requireLogin,(req,res) =>{
    User.findById({_id:req.user._id})
    .then((user) => {
        user.fullname = req.body.fullname;
        user.email = req.body.email;
        user.gender = req.body.gender;
        user.about = req.body.about;
        user.save(() => {
            res.redirect('/profile');
        });
    }); 
});
app.get('/askToDelete',requireLogin,(req,res) => {
    res.render('askToDelete',{
        title: 'Delete'
    });
});
app.get('/deleteAccount',requireLogin,(req,res) =>{
    User.deleteOne({_id:req.user._id})
    .then(() => {
        res.render('accountDeleted',{
            title:'Deleted'
        });
    });
});
app.get('/newAccount',(req,res) => {
    res.render('newAccount',{
        title: 'Signup'
    });
});
app.post('/signup',(req,res) => {
    console.log(req.body);
    let errors = [];

    if(req.body.password !== req.body.password2) {
        errors.push({text:'Password does not match'});
    }
    if(req.body.password.length < 5){
        errors.push({text:'Password must be at least 5 characters'});
    }
    if (errors.length > 0){
        res.render('newAccount',{
            errors: errors,
            title: 'Error',
            fullname: req.body.username,
            email: req.body.email,
            password: req.body.password,
            password2: req.body.password2
        });    
    }else{
        User.findOne({email:req.body.email})
        .then((user) => {
            if (user) {
                let errors = [];
                errors.push({text:'Email already exists'});
                res.render('newAccount',{
                    title:'Signup',
                    errors:errors
                })
            }else{
                var salt = bcrypt.genSaltSync(10);
                var hash = bcrypt.hashSync(req.body.password, salt);
                const newUser = {
                    fullname: req.body.username,
                    email: req.body.email,
                    password: hash
                }
                new User(newUser).save((err,user) =>{
                    if (err){
                        throw err;
                    }
                    if (user){
                        let success = [];
                        success.push({text:'You have successfully created an account. You can login now'});
                        res.render('home',{
                           success: success 
                        });
                    }
                });
            }
        });
    }    
});
app.post('/login',passport.authenticate('local',{
    successRedirect:'/profile',
    failureRedirect:'/loginErrors'
}));
app.get('/loginErrors', (req,res) => {
    let errors = [];
    errors.push({text:'User Not found or Password Incorrect'});
    res.render('home',{
        errors:errors
    });
    
});
// handle get route
app.get('/uploadImage',requireLogin,(req,res) => {
    res.render('uploadImage',{
        title: 'Upload'
    });
});
app.post('/uploadAvatar',requireLogin,(req,res) => {
    User.findById({_id:req.user._id})
    .then((user) => {
        user.image = `https://onlinedatingappb.s3.amazonaws.com/${req.body.upload}`;
        user.save((err) =>{
            if (err){
                throw err;
            }
            else{
                res.redirect('/profile');
            }
        });
    });
});

app.post('/uploadFile',requireLogin,uploadImage.any(),(req,res) =>{
    const form = new formidable.IncomingForm();
    form.on('file',(field,file) => {
        console.log(file);
    });
    form.on('error',(err) => {
        console.log(err);
    });
    form.on('end',() => {
        console.log('Image upload is successfull ..');
    });
    form.parse(req);
});
//handle Get route for users
app.get('/singles',requireLogin,(req,res) => {
    User.find({})
    .sort({date:'desc'})
    .then((singles) => {
        res.render('singles',{
            title:'Singles',
            singles:singles
        })
    }).catch((err) => {
        console.log(err);
    });
});

app.get('/userProfile/:id',(req,res) => {
    User.findById({_id:req.params.id})
    .then((user) => {
        res.render('userProfile',{
            title:'Profile',
            oneUser: user
        });
    });
});
// START CHAT PROCESS
app.get('/startChat/:id',requireLogin,(req,res) =>{
    Chat.findOne({sender:req.params.id,receiver:req.user._id})
    .then((chat) =>{
        if(chat) {
            chat.receiverRead = true;
            chat.senderRead = false;
            chat.date = new Date();
            chat.save((err,chat) => {
                if(err){
                    throw err;
                }
                if (chat) {
                    res.redirect(`/chat/${chat._id}`);
                }
            })
        }else{
            Chat.findOne({sender:req.user._id,receiver:req.params.id})
            .then((chat) =>{
                if (chat) {
                    chat.senderRead = true;
                    chat.receiverRead = false;
                    chat.date = new Date();
                    chat.save((err,chat) =>{
                        if(err){
                            throw err;
                        }
                        if (chat) {
                            res.redirect(`/chat/${chat._id}`);
                        }
                    })
                }else{
                    const newChat = {
                        sender: req.user._id,
                        receiver: req.params.id,
                        senderRead: true,
                        receiverRead: false,
                        date: new Date()
                    }
                    new Chat(newChat).save((err,chat) => {
                        if(err){
                            throw err;
                        }
                        if (chat){
                            res.redirect(`/chat/${chat._id}`);
                        }
                    })
                }
            })
        }
    })
})
// Display Chat Room
app.get('/chat/:id',requireLogin,(req,res) => {
    Chat.findById({_id:req.params.id})
    .populate('sender')
    .populate('receiver')
    .populate('chats.senderName')
    .populate('chats.receiverName')
    .then((chat) => {
        User.findOne({_id:req.user._id})
        .then((user) => {
            res.render('chatRoom',{
                title:'Chat',
                user:user,
                chat:chat
            })
        })
    })
})
app.post('/chat/:id',requireLogin,(req,res) => {
    Chat.findOne({_id:req.params.id,sender:req.user._id})
    .sort({date:'desc'})
    .populate('sender')
    .populate('receiver')
    .populate('chats.senderName')
    .populate('chats.receiverName')
    .then((chat) => {
        if(chat){
            // sender sends message here
            chat.senderRead = true;
            chat.receiverRead = false;
            chat.date = new Date();

            const newChat = {
                senderName:req.user._id,
                senderRead: true,
                receiverName: chat.receiver._id,
                receiverRead: false,
                date: new Date(),
                senderMessage: req.body.chat
            }
            chat.chats.push(newChat)
            chat.save((err,chat) => {
                if(err) {
                    throw err;
                }
                if(chat){
                    Chat.findOne({_id:chat._id})
                    .sort({date:'desc'})
                    .populate('sender')
                    .populate('receiver')
                    .populate('chats.senderName')
                    .populate('chats.receiverName')
                    .then((chat) => {
                        User.findById({_id:req.user._id})
                        .then((user) => {
                            // we will charge client for each message
                            user.wallet = user.wallet - 1;
                            user.save((err,user) =>{
                                if(err){
                                    throw err;
                                }
                                if(user){
                                    res.render('chatRoom',{
                                        title:'Chat',
                                        chat:chat,
                                        user:user
                                    })
                                }
                            })
                        })
                    })
                }
            })
        }
        // receiver sends message back
        else{
            Chat.findOne({_id:req.params.id,receiver:req.user._id})
            .sort({date:'desc'})
            .populate('sender')
            .populate('receiver')
            .populate('chats.senderName')
            .populate('chats.receiverName')
            .then((chat) => {
                chat.senderRead = true;
                chat.receiverRead = false;
                chat.date = new Date();
                const newChat = {
                    senderName: chat.sender._id,
                    senderRead: false,
                    receiverName: req.user._id,
                    receiverRead: true,
                    receiverMessage: req.body.chat,
                    date: new Date()
                }
                chat.chats.push(newChat)
                chat.save((err,chat) =>{
                    if(err) {
                        throw err;
                    }
                    if(chat) {
                        Chat.findOne({_id:chat._id})
                        .sort({date:'desc'})
                        .populate('sender')
                        .populate('receiver')
                        .populate('chats.senderName')
                        .populate('chats.receiverName')
                        .then((chat) =>{
                            User.findById({_id:req.user._id})
                            .then((user) =>{
                                user.wallet = user.wallet - 1;
                                user.save((err,user) => {
                                    if(err){
                                        throw err;
                                    }
                                    if(user){
                                        res.render('chatRoom',{
                                            title: 'Chat',
                                            user:user,
                                            chat:chat

                                        })
                                    }
                                })
                            })
                        })
                    }
                })
            })
        }
    })
})
app.get('/logout',(req,res) => {
    User.findById({_id:req.user._id})
    .then((user) => {
        user.online = false;
        user.save((err,user) => {
            if (err) {
                throw err;
            }
            if (user) {
                req.logout();
                res.redirect('/');
            }
        })
    })  
});

app.post('/contactUs',(req,res) => {
    console.log(req.body);
    const newMessage = {
        fullname: req.body.fullname,
        email: req.body.email,
        message: req.body.message,
        date: new Date()
    }
    new Message(newMessage).save((err,message) => {
        if (err) {
            throw err;
        }else{
            Message.find({}).then((messages) => {
                if (messages) {
                    res.render('newmessage',{
                        title:'Sent',
                        messages:messages
                    });
                }else{
                    res.render('noMessage', {
                        title: 'Not Found'
                    });
                }
            });
        }
    });
});
app.listen(port,() => {
  console.log(`Server is running on port ${port}`);  
});

