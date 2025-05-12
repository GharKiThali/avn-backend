const express = require("express");
const router = express.Router();

const { register, userLogin, sendOtp, verifyOtp,validate} = require("../controller/userControllers");


router.post("/signup", register);
router.post("/login", userLogin);
router.post("/sendOtp", sendOtp);  // Route for sending OTP
router.post("/VerifyOtp", verifyOtp); 
router.get("/validate",validate) // Route for verifying OTP

module.exports = router;
