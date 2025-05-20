


const bcrypt = require('bcryptjs');
const userModel = require('../models/user.model');
const nodemailer = require('nodemailer');


const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false, // use TLS
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});


const otpStore = {}; // Temporary OTP store

// Send OTP
exports.sendOTP = async (req, res) => {
  const { email } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000);
  otpStore[email] = otp;

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Your OTP Code',
    text: `Your OTP is: ${otp}`,
  };

  try {
    await transporter.sendMail(mailOptions);
    res.send({ message: 'OTP sent to your email!' });
  } catch (error) {
    console.error('Error sending OTP:', error);
    res.status(500).send({ message: 'Error sending OTP' });
  }
};

// Verify OTP
exports.verifyOTP = (req, res) => {
  const { email, otp } = req.body;

  if (otpStore[email] && otpStore[email] == otp) {
    res.send({ message: 'OTP verified successfully!' });
  } else {
    res.status(400).send({ message: 'Invalid OTP' });
  }
};



// Reset Password

exports.resetPassword = async (req, res) => {
  const { email, newPassword } = req.body;

  console.log("Reset password request received for:", email);

  // Validation
  if (!email || !newPassword) {
    return res.status(400).send({ message: 'Email and new password are required.' });
  }

  // Check OTP
  if (!otpStore[email]) {
    console.log("OTP not verified or expired for:", email);
    return res.status(400).send({ message: 'OTP not verified or expired!' });
  }

  try {
    // Find user by email
    const user = await userModel.findOne({ email });
    if (!user) {
      console.log("User not found:", email);
      return res.status(404).send({ message: 'User not found' });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update user password
    user.password = hashedPassword;
    await user.save();

    // Clear OTP
    delete otpStore[email];

    console.log("Password reset successful for:", email);
    return res.status(200).send({ message: 'Password reset successful!' });

  } catch (error) {
    console.error('Error resetting password:', error);
    return res.status(500).send({ 
      message: 'Something went wrong, please try again later.',
      error: error.message
    });
  }
};





