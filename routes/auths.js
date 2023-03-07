const express = require('express');
const router = express.Router();
const {getAllAuth, getSingleAuth, createAuth, updateAuth, deleteAuth} = require('../controllers/authCtrls');

router.route('/').get(getAllAuth).post(createAuth);
router.route('/:id').get(getSingleAuth).delete(deleteAuth).patch(updateAuth)


module.exports = router