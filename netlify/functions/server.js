require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

// Middleware
app.use(bodyParser.json());

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// MongoDB connection
const uri = process.env.MONGODB_URI;
if (!uri) {
  console.error('MONGODB_URI is not defined');
} else {
  console.log(`Connecting to MongoDB with URI: ${uri}`);
}
mongoose.connect(uri, { serverSelectionTimeoutMS: 5000 })
  .then(() => console.log('MongoDB connected'))
  .catch(err => {
    console.error('MongoDB connection error:', err);
    console.error('Error details:', JSON.stringify(err, null, 2));
});


const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});


const user = mongoose.model('user', userSchema);

// Generate verification token
const createVerificationToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '1d' });
};

// Configure Nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS,
  },
});


const sendVerificationEmail = async (email, token) => {
  const verificationUrl = `https://ivoire-artisans-verif.netlify.app?token=${encodeURIComponent(token)}`;
  console.log('Generated verification URL:', verificationUrl);

  const mailOptions = {
    from: process.env.GMAIL_USER,
    to: email,
    subject: 'Verify your email',
    html: `
      <html>
        <body>
          <p>Please verify your email by clicking on the following link:</p>
          <p><a href="${verificationUrl}" target="_blank" rel="noopener noreferrer">Verify Email</a></p>
          <p>If you did not request this, please ignore this email.</p>
        </body>
      </html>
    `,
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log('Verification email sent to:', email);
    console.log('Email response:', info.response);
  } catch (error) {
    console.error('Error sending verification email:', error);
  }
};

// routes
app.post('/api/users', async (req, res) => {
  const saltRounds = 10;
  const { username, email, password } = req.body;
  try {
    const existingUser = await user.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const newUser = new User({ username, email, password: hashedPassword }); // Updated here
    await newUser.save();

    const token = createVerificationToken(newUser._id);
    console.log('THE TOKEN:', token);
    await sendVerificationEmail(email, token);

    res.status(201).json({ message: 'User created successfully. Please check your email to verify your account.' });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ message: 'Error creating user', error: error.message });
  }
});


if (process.env.NODE_ENV === 'development') {
    const PORT = process.env.PORT;
    app.listen(PORT, () => {
      console.log(`Server is running on http://192.168.1.90:${PORT}`);
    });
} else {
  module.exports.handler = serverless(app);
}