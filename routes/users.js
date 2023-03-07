const express = require('express')
const router = express.Router();
const {authMW, adminOnly, authorOnly} = require('../middleware/authMiddleware')
const {logOutUser, loginUser, registerUser, getUser,verifyLoginCode, updateUser,forgotPassword,changePassword,resetPassword,sendLoginCode, deleteUser, getAllUsers,verificationEmail,verifyUser,loginStatus,upgradeUser,sendAutomatedEmail} = require('../controllers/userCtrls');

router.post('/register',registerUser);
router.post('/login',loginUser);
router.get('/logout',logOutUser);
router.get("/getUser",authMW, getUser)
router.patch('/updateUser',authMW, updateUser)
router.delete('/:id', authMW, adminOnly, deleteUser)
router.get("/getAllUsers",authMW, authorOnly, getAllUsers)
router.get('/loginStatus', loginStatus)
router.post('/upgradeUser',authMW, adminOnly, upgradeUser)
router.post('/sendAutoEmail',authMW, sendAutomatedEmail)
router.post('/sendVerificationEmail',authMW, verificationEmail)
router.patch('/verifyUser/:verificationToken', verifyUser)
router.post("/forgotPassword", forgotPassword)
router.patch("/resetPassword/:resetToken", resetPassword)
router.patch("/changePassword",authMW, changePassword)
router.post("/sendLoginCode/:email", sendLoginCode)
router.post('/loginWithCode/:email', verifyLoginCode)

module.exports = router;