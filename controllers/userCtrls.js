const asyncHandler = require('express-async-handler');
const User = require("../model/userModel")
const {generateToken, hashToken} = require("../utils")
const parser = require('ua-parser-js')
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sendEmail = require('../utils/sendEmails');
const Token = require('../model/tokenModel');
const crypto = require('crypto');
const Cryptr = require('cryptr');
const cryptr = new Cryptr(process.env.CRYPTR_KEY);

const registerUser = asyncHandler(async(req,res)=>{
    const {name, email, password, role} = req.body;
    //validation
    if(!name || !email || !password){
        res.status(400)
        throw new Error('Please fill in all the required fields')
    }
    if(password.length < 6){
        res.status(400)
        throw new Error('Password must be up to 6 characters')
    }
    // check users existence on database
    const userExist = await User.findOne({email});

    if(userExist){
        res.status(400)
        throw new Error('Email already in use') 
    };

    // get user agent
    const ua = parser(req.headers['user-agent']);
    const userAgent = [ua.ua]

    // create new User
    const user = await User.create({name,email,password,role, userAgent});

    // generate jwt and pass the cookie
    const token = generateToken(user._id);

    // send http-only cookie
    res.cookie('token', token,{
        httpOnly:true,
        expires:new Date(Date.now() + 1000 * 86400),
        secure: process.env.NODE_ENV === "production",
        signed:true
    });

    if(user){
        const {_id, name, photo,email, isVerified, phone, bio, role} = user
        res.status(201).json({
            _id, name, photo, isVerified, phone,email, bio, role,token
        })
    }else{
        res.status(400)
        throw new Error('Invalid user data')
    }
});

const loginUser = asyncHandler(async(req,res)=>{
    const {email,password} = req.body
    // Validation
    if(!email || !password){
        res.status(400)
        throw new Error('Email already in use') 
    }
    
    const user = await User.findOne({email})
    if(!user){
        res.status(400)
        throw new Error('User not found. Please signup.') 
    }
    const passwordIsCorrect = await bcrypt.compare(password, user.password);
    if(!passwordIsCorrect){
        res.status(400)
        throw new Error('Invalid email or password.') 
    }
    // Trigger 2FA to check if user device(user agent) is registered
    const ua = parser(req.headers['user-agent']);
    const thisUserAgent = ua.ua;
    const allowedAgent = user.userAgent.includes(thisUserAgent);

    if(!allowedAgent){
        // generate 6 digit code
        const loginCode = Math.floor(100000 + Math.random() * 900000)
        const encryptedCode = cryptr.encrypt(loginCode.toString())
        // check if token if it exist in DB
        let userToken = await Token.findOne({userId : user._id});
        if(userToken){
            await userToken.deleteOne()
        }
        
        await new Token({
            userId : user._id,
            loginToken : encryptedCode,
            createdAt :  Date.now(),
            expiresAt : Date.now() + 60 * (60 * 1000) //1hour
        }).save();
        res.status(400)
        throw new Error("New browser or device detected")
    }

    // check if the users device is authorized, then trigger 2FA for unknown user agent
    const token = generateToken(user._id);
    if(user && password){
        // send http-only cookie
        res.cookie('token', token,{
            httpOnly:true,
            expires:new Date(Date.now() + 1000 * 86400),
            secure: process.env.NODE_ENV === "production",
            signed:true
        });

        const {_id, name, photo, isVerified, phone, bio, role } = user
        res.status(201).json({
            _id, name, photo, isVerified, phone, bio, role, token
        })
    }else{
        res.status(500)
        throw new Error('Somethimg went wrong. Please try again') 
    }
});

const logOutUser =asyncHandler(async(req,res)=>{
    res.cookie('token', "",{
        httpOnly:true,
        expires:new Date(0),
        secure: process.env.NODE_ENV === "production",
        signed:true
    });
    res.status(200).json({msg:"Log out successful"})
});

const getUser = asyncHandler(async(req,res)=>{
    const user = await User.findById(req.user._id);
    if(user){
        const {_id, name, photo, isVerified, phone, bio, role } = user
        
        res.status(200).json({
            _id, name, photo, isVerified, phone, bio, role
        })
    }else{
        res.status(404)
        throw new Error('User not found') 
    }
})

const updateUser = asyncHandler(async(req,res)=>{
    const user = await User.findById(req.user._id);
    if (user) {
        const {name, photo, phone, bio, email,isVerified, role } = user;
        user.name = req.body.name || name;
        user.photo = req.body.photo || photo;
        user.phone = req.body.phone || phone;
        user.bio = req.body.bio || bio;
        user.isVerified = req.body.isVerified || isVerified;
        user.role = req.body.role || role;
        user.email = email

        const updatedUser = await user.save()
        res.status(200).json({
            name:updatedUser.name, 
            photo:updatedUser.photo,
            phone:updatedUser.phone, 
            bio:updatedUser.bio,
            role:updatedUser.role,
            isVerified:updatedUser.isVerified, 
            email:updatedUser.email
        })
    } else {
        res.status(404)
        throw new Error('User not found') 
    }
});

const deleteUser = asyncHandler(async(req,res)=>{
    const {id:userId} = req.params;
    // const {id:userId} = req.body;
    const user = await User.findById(userId);
    if(!user){
        res.status(404)
        throw new Error('User not found') 
    }
    await User.deleteOne()
    res.status(200).json({msg:"User deleted successfully"})
});

const getAllUsers = asyncHandler(async(req,res)=>{
    const user = await User.find().sort("-createdAt").select('-password');
    if(!user){
        res.status(500)
        throw new Error('Something went wrong')
    }
    res.status(200).json(user)
});

const loginStatus = asyncHandler(async(req,res)=>{
    const token = req.signedCookies.token;
    
    if(!token){
        return res.json({status: false, msg:"User not logged In"})
    }
    const verified = jwt.verify(token, process.env.JWT_SECRET)
    if(verified){
        return res.json({status: true, msg:"User logged In"})
    }
    return res.json({status: false, msg:"Something went wrong"})
});

const upgradeUser = asyncHandler(async(req,res)=>{
    const {id:userId, role} = req.body;
    const user = await User.findById(userId);
    if(!user){
        res.status(404)
        throw new Error('User not found')
    }else{
        user.role = role
        await user.save()
        res.status(200).json(user)
    }
});

const sendAutomatedEmail = asyncHandler(async(req, res)=>{
    const {subject, send_to, reply_to, template, url} = req.body
    if(!subject || !send_to || !reply_to || !template){
        res.status(404)
        throw new Error('Missing email parameter');
    }
    // get user
    const user = await User.findOne({email : send_to})
    if(!user){
        res.status(404)
        throw new Error('User not found');
    }

    const sent_from = process.env.EMAIL_USER;
    const name = user.name;
    const link =`${process.env.FRONTEND_URL}${url}`;

    try {
        await sendEmail(subject, send_to, sent_from, reply_to, template, name, link)
        res.status(200).json({msg:"Email sent"})
    } catch (error) {
        res.status(500)
        throw new Error('Email not sent. Please try again');
    }
});

// send verification email
const verificationEmail = asyncHandler(async(req,res)=>{
    const user = await User.findById(req.user._id)
    if(!user){
        res.status(400)
        throw new Error('User not found.') 
    }
    if(user.isVerified){
        res.status(400)
        throw new Error('User already verified')
    }

    // delete token if it exist in DB
    let token = await Token.findOne({userId : user._id});
    if(token){
        await Token.deleteOne()
    }

    // create verification token and save in DB
    const verificationToken = crypto.randomBytes(32).toString("hex") + user._id;
    
    // hash token and save. This gives added security to the token
    const hashedToken = hashToken(verificationToken);
    await new Token({
        userId : user._id,
        verificationToken : hashedToken,
        createdAt :  Date.now(),
        expiresAt : Date.now() + 60 * (60 * 1000) //1hour
    }).save();

    // construct verification url
    const verificationUrl = `${process.env.FRONTEND_URL}/verify/${verificationToken}`

    // send email
    const subject = 'Verify Your Account - HR-Mgt'
    const send_to = user.email
    const sent_from = process.env.EMAIL_USER 
    const reply_to = "noreply@raphael.com"
    const template = 'verifyEmail'
    const name = user.name
    const link = verificationUrl

    try {
        await sendEmail(subject, send_to, sent_from, reply_to, template, name, link)
        res.status(200).json({msg:"Verification Email sent"})
    } catch (error) {
        res.status(500)
        throw new Error('Email not sent. Please try again');
    }
});

const verifyUser = asyncHandler(async(req,res)=>{
    const {verificationToken} = req.params;
    const hashedToken = hashToken(verificationToken);

    const userToken = await Token.findOne({
        verificationToken : hashedToken,
        expiresAt : {$gt : Date.now()}
    });

    if(!userToken){
        res.status(404)
        throw new Error('Expired Token')
    }
    // find user 
    const user = await User.findOne({_id : userToken.userId});
    if(user.isVerified === true){
        res.status(400)
        throw new Error('User already verified')
    }
    user.isVerified = true;
    await user.save();
    res.status(200).json({msg:"Account verification successful"})
});

const forgotPassword = asyncHandler(async(req, res)=>{
    const {email} = req.body;

    const user = await User.findOne({email});
    if(!user){
        res.status(404)
        throw new Error("No User with this email")
    }
    // check if token if it exist in DB
    let token = await Token.findOne({userId : user._id});
    if(token){
        await Token.deleteOne()
    }

    // create reset token and save in DB
    const resetToken = crypto.randomBytes(32).toString("hex") + user._id;
    
    // hash token and save. This gives added security to the token
    const hashedToken = hashToken(resetToken);
    await new Token({
        userId : user._id,
        resetToken : hashedToken,
        createdAt :  Date.now(),
        expiresAt : Date.now() + 60 * (60 * 1000) //1hour
    }).save();

    // construct reset url
    const resetUrl = `${process.env.FRONTEND_URL}/verify/${resetToken}`

    // send email
    const subject = 'Password reset- HR-Mgt'
    const send_to = user.email
    const sent_from = process.env.EMAIL_USER 
    const reply_to = "noreply@raphael.com"
    const template = 'forgotPassword'
    const name = user.name
    const link = resetUrl

    try {
        await sendEmail(subject, send_to, sent_from, reply_to, template, name, link)
        res.status(200).json({msg:"Reset Email sent"})
    } catch (error) {
        res.status(500)
        throw new Error('Email not sent. Please try again');
    }
});

const resetPassword = asyncHandler(async(req,res)=>{
    const {resetToken} = req.params;
    const {password} = req.body;
    const hashedToken = hashToken(resetToken);

    const userToken = await Token.findOne({
        resetToken : hashedToken,
        expiresAt : {$gt : Date.now()}
    });
    
    if(!userToken){
        res.status(404)
        throw new Error('Expired Token')
    }
    
    // find user 
    const user = await User.findOne({_id : userToken.userId});
    user.password = password
    await user.save();
    res.status(200).json({msg:"Password reset successful. Please login"})
});

const changePassword = asyncHandler(async(req,res)=>{
    const {oldPassword, password} = req.body;
    const user = await User.findById(req.user._id)

    if(!user){
        res.status(404)
        throw new Error('User not found')
    };

    if(!oldPassword || !password){
        res.status(404)
        throw new Error('Please enter old and new password')
    }
    
    const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password);
    if(passwordIsCorrect && user){
        user.password = password;
        await user.save();
        res.status(200).json({msg:"Password changed was succesful. Please login"})
    }else{
        res.status(400)
        throw new Error('Old password is incorrect')
    }
});

const sendLoginCode = asyncHandler(async(req,res)=>{
    const {email} = req.params;
    const user = await User.findOne({email});
    
    if(!user){
        res.status(404)
        throw new Error('User not found')
    }
    console.log(user._id)
    // find login token of that user in the DB
    let token = await Token.findOne({
        userId : user._id,
        expiresAt : {$gt : Date.now()}
    });

    if(!token){
        res.status(404)
        throw new Error('Expired Token. Please login again')
    }
    const loginCode = token.loginToken
    const decryptedCode = cryptr.decrypt(loginCode.toString())
    
    // send email
    const subject = 'LOGIN ACCESS CODE- HR-Mgt'
    const send_to = email
    const sent_from = process.env.EMAIL_USER 
    const reply_to = "noreply@raphael.com"
    const template = 'loginCode'
    const name = user.name
    const link = decryptedCode

    try {
        await sendEmail(subject, send_to, sent_from, reply_to, template, name, link)
        res.status(200).json({msg:`Access code sent to ${email}`})
    } catch (error) {
        res.status(500)
        throw new Error('Access code not sent. Please try again');
    }
});

// login with code
const verifyLoginCode = asyncHandler(async(req,res)=>{
    const {email} = req.params;
    const {loginCode} = req.body;

    const user = await User.findOne({email})
    if(!user){
        res.status(404)
        throw new Error('No User found')
    }
    const token = await Token.findOne({
        userId : user._id,
        expiresAt: {$gt :Date.now()}
    });
    if(!token){
        res.status(404)
        throw new Error('Invalid or expired Token. Please login again')
    }
    const decryptedCode = cryptr.decrypt(token.loginToken);
    if(loginCode !== decryptedCode){
        res.status(404)
        throw new Error('Incorrect login code please try again')
    }else{
        // register user agent
        const ua = parser(req.headers['user-agent']);
        const userAgent = ua.ua;
        user.userAgent.push(userAgent)
        await user.save();

        // generate jwt and pass the cookie
        const token = generateToken(user._id);

        // send http-only cookie
        res.cookie('token', token,{
            httpOnly:true,
            expires:new Date(Date.now() + 1000 * 86400),
            secure: process.env.NODE_ENV === "production",
            signed:true
        });

        const {_id, name, photo,email, isVerified, phone, bio, role} = user
        res.status(201).json({
            _id, name, photo, isVerified, phone,email, bio, role
        })
    }
})

module.exports = {sendLoginCode,logOutUser,verifyLoginCode,forgotPassword,changePassword,loginUser, registerUser, getUser, updateUser, deleteUser,resetPassword, getAllUsers,verificationEmail, loginStatus, upgradeUser,verifyUser, sendAutomatedEmail}