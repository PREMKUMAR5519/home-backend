const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { sendOTP } = require('../utils/email');
require('dotenv').config();

const register = async (req, res) => {
    const { name, email, password } = req.body;

    try {
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ msg: 'User already exists' });
        }

        user = new User({
            name,
            email,
            password,
        });

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        user.otp = otp;
        user.otpExpires = Date.now() + 10 * 60 * 1000; // 10 minutes

        await user.save();

        await sendOTP(email, otp);

        res.status(200).json({ msg: 'OTP sent to email' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
};

const verifyOTP = async (req, res) => {
    const { email, otp } = req.body;

    try {
        let user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ msg: 'Invalid email or OTP' });
        }

        if (user.otp !== otp || user.otpExpires < Date.now()) {
            return res.status(400).json({ msg: 'Invalid OTP or OTP expired' });
        }

        user.isVerified = true;
        user.otp = undefined;
        user.otpExpires = undefined;

        await user.save();

        res.status(200).json({ msg: 'Email verified successfully' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
};

const resendOTP = async (req, res) => {
    const { email } = req.body;

    try {
        let user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ msg: 'User does not exist' });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        user.otp = otp;
        user.otpExpires = Date.now() + 10 * 60 * 1000; // 10 minutes

        await user.save();

        await sendOTP(email, otp);

        res.status(200).json({ msg: 'OTP resent to email' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
};

const login = async (req, res) => {
    const { email, password } = req.body;

    try {
        let user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ msg: 'Invalid email or password' });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid email or password' });
        }

        if (!user.isVerified) {
            return res.status(400).json({ msg: 'Email not verified' });
        }

        const payload = {
            user: {
                id: user.id,
            },
        };

        jwt.sign(
            payload,
            process.env.JWT_SECRET,
            { expiresIn: 3600 },
            (err, token) => {
                if (err) throw err;
                res.json({ token });
            }
        );
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
};

module.exports = { register, verifyOTP, resendOTP, login };
