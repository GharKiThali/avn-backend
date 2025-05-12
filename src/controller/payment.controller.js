const paymentModel = require('../models/payment.model');
const Razorpay = require('razorpay');
console.log('RAZORPAY_KEY_ID:', process.env.RAZORPAY_KEY_ID);
console.log('RAZORPAY_KEY_SECRET:', process.env.RAZORPAY_KEY_SECRET);

const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID.trim(),
    key_secret: process.env.RAZORPAY_KEY_SECRET.trim(),
});


const paymentcreate = async (req, res) => {
    const { name, email, adhar, address, occupation, street,city,state,pincode,gender } = req.body;
    console.log(req.body);
    const options = {
        amount: req.body.amount * 100, // amount in paisa (₹50.00)
        currency: "INR",
    };
    console.log(options);
    try {
        const order = await razorpay.orders.create(options);


        const newPayment = await paymentModel.create({
            orderId: order.id,
            amount: order.amount,
            currency: order.currency,
            name: name,
            email: email,
            adhar: adhar,
            address: address,
            occupation: occupation,
            street: street,
            city: city,
            state: state,
            pincode: pincode,
            gender: gender,
            status: 'pending',
        });


        console.log('Order Created:', newPayment);

        return res.json({ order, newPayment }); // Ensure response is sent
    } catch (error) {
        console.error('Error creating order:', error);
        res.status(500).json({ message: 'Error creating order', error: error.message });
    }
}


const paymentverify = async (req, res) => {
    const { razorpayOrderId, razorpayPaymentId, signature } = req.body;
    console.log(req.body);
    const secret = process.env.RAZORPAY_KEY_SECRET.trim();

    try {
        const { validatePaymentVerification } = require('razorpay/dist/utils/razorpay-utils');

        const isValid = validatePaymentVerification(
            { order_id: razorpayOrderId, payment_id: razorpayPaymentId },
            signature,
            secret
        );

        if (isValid) {
            const payment = await paymentModel.findOne({ orderId: razorpayOrderId });

            if (!payment) {
                return res.status(404).json({ message: 'Payment record not found' });
            }

            payment.paymentId = razorpayPaymentId;
            payment.signature = signature;
            payment.status = 'completed';
            await payment.save();

            return res.json({ status: 'success' });
        } else {
            return res.status(400).json({ message: 'Invalid signature' });
        }
    } catch (error) {
        console.error('Error verifying payment:', error);
        res.status(500).json({ message: 'Error verifying payment', error: error.message });
    }
}







const getPaymentHistory = async (req, res) => {
  const { adhar } = req.body;

  if (!adhar || adhar.length !== 12) {
    return res.status(400).json({ message: "Invalid Aadhaar number" });
  }

  try {
    const history = await paymentModel.find({ adhar }).sort({ createdAt: -1 }); // latest first

    if (!history.length) {
      return res.status(404).json([]); // empty list if not found
    }

    res.status(200).json(history);
  } catch (error) {
    console.error("Payment history error:", error);
    res.status(500).json({ message: "Server error" });
  }
};



module.exports = { paymentcreate, paymentverify ,getPaymentHistory };