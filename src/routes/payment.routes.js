const express = require('express');
const { paymentcreate, paymentverify, getPaymentHistory } = require('../controller/payment.controller.js');
const router = express.Router();



router.post('/paymentcreate',paymentcreate);

router.post('/paymentverify', paymentverify);

router.post('/payHistory',getPaymentHistory);

module.exports = router;

