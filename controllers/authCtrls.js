const getAllAuth = (req,res)=>{
    res.send("GET ALL AUTHS")
}

const getSingleAuth = (req,res)=>{
    res.send("GET SINGLE AUTHS")
}

const createAuth = (req,res)=>{
    res.send("CREATE AUTHS")
}

const updateAuth = (req,res)=>{
    res.send("UPDATE AUTHS")
}

const deleteAuth = (req,res)=>{
    res.send("DELETE AUTHS")
}

module.exports = {getAllAuth, getSingleAuth, createAuth, updateAuth, deleteAuth}