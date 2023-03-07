const asyncHandler = require('express-async-handler')
const User = require('../model/userModel')
const jwt = require('jsonwebtoken')

const authMW = asyncHandler(async(req,res,next)=>{
    try {
        const token = req.signedCookies.token
        
        // verification
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        // Get User id from verified
        const user = await User.findById(verified.id).select('-password')
        
        if(!user){
            res.status(404)
            throw new Error('User not found')
        }
        if(user.role === 'suspended'){
            res.status(400)
            throw new Error('User suspended. Please contact support')
        }
        req.user = user;
        next()
    } catch (error) {  
        if(error){
            console.log(error)
            res.status(401)
            throw new Error('Not Authorized, please login')
        } 
    }

});

const adminOnly = asyncHandler(async(req,res,next)=>{
    if(req.user && req.user.role === 'admin'){
        next()
    }else{
        res.status(401)
        throw new Error('Not Authorized as an admin')
    }
});

const authorOnly = asyncHandler(async(req,res,next)=>{
    if(req.user.role === "author" || req.user.role === 'admin'){
        next()
    }else{
        res.status(401)
        throw new Error('Not Authorized as an author')
    }
})

module.exports = {authMW, authorOnly, adminOnly}