require('dotenv').config()
const express = require('express')
const app = express()
const cookieParser = require('cookie-parser')
const cors = require('cors')
const connectDB = require('./db/connect')
const authRouter = require('./routes/auths')
const userRouter = require('./routes/users')
const errorHandler = require('./middleware/error-handler')

app.use(cookieParser(process.env.JWT_SECRET))
app.use(express.urlencoded({extended:false}));
app.use(express.json())
app.use(cors({
    origin: ["http://localhost:5000"],
    credentials:true
}))

app.use("/api/v1/auth", authRouter)
app.use("/api/v1/user", userRouter)

app.use(errorHandler)

const port = process.env.PORT;
const start = async()=>{
    try {
        await connectDB(process.env.MONGO_URL)
        app.listen(port, ()=>console.log(`Server is listening on PORT ${port}`))
    } catch (error) {
        console.log(error)
    }
}
start()