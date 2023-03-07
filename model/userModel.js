const mongoose = require("mongoose");
const bcrypt = require('bcryptjs');;

const userSchema = mongoose.Schema({
    name:{
        type:String,
        required : [true, 'Please provide a name']
    },
    email:{
        type:String,
        required : [true, 'Please provide an email'],
        trim:true,
        unique: true,
        match: [
            /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
            "Please enter a valid email",
        ],
    },
    password:{
        type:String,
        required : [true, 'Please add your password']
    },
    photo:{
        type:String,
        required : [true, 'Please add a photo'],
        default : "https://i.ibb.co/4pDNDk1/avatar.png"
    },
    phone:{
        // type:String,
        type: Number,
        default:"234"
    },
    bio:{
        type:String,
        default:'Bio'
    },
    role:{
        type:String,
        required : true,
        default:"subscriber"
    },
    isVerified:{
        type:Boolean,
        default : false
    },
    userAgent:{
        type:Array,
        default: [],
        required:true
    }
},{ timestamps: true });

// Encrypt password before saving to DB
userSchema.pre("save", async function(next){
    if(!this.isModified("password")){
        next()
    }else{
        // hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPWD = await bcrypt.hash(this.password, salt);
        this.password = hashedPWD
        next()
    }
})

module.exports = mongoose.model("User", userSchema)