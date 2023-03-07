require('dotenv').config()
const connectDB = require('./db/connect');
const Store = require('./models/store')

const jsonProducts = require('./products.json');

const start = async()=>{
    try {
        await connectDB(process.env.MONGO_URL);
        await Store.deleteMany();
        await Store.create(jsonProducts);
        console.log("populate successful!!!")
        process.exit(0)
    } catch (error) {
        console.log(error)
        process.exit(1)
    }
};
start()