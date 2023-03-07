require('dotenv').config()
const connectDB = require('./db/connect');
const tokenModel = require('./model/tokenModel');
const User = require('./model/userModel')


// const jsonProducts = require('./products.json');

const start = async()=>{
    try {
        await connectDB(process.env.MONGO_URL);
        await tokenModel.deleteMany();
        console.log("delete successful!!!")
        process.exit(0)
    } catch (error) {
        console.log(error)
        process.exit(1)
    }
};
start()