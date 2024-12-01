const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const User = require('./models/user');

const app = express();
const port = 5000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));  // Serving static files like CSS, images, etc.


// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/project3')
    .then(() => console.log("Connected to MongoDB"))
    .catch((err) => console.log(err));

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html')); // Serve index.html
});

app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'signup.html')); // Serve signup.html
});

app.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
        username,
        email,
        password: hashedPassword
    });

    await newUser.save();
    res.redirect('/signin'); // Redirect to signin after successful signup
});

app.get('/signin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'signin.html')); // Serve signin.html
});

app.post('/signin', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
        return res.status(400).send('User not found');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).send('Invalid credentials');
    }

    const token = jwt.sign({ userId: user._id }, 'your_jwt_secret');
    res.cookie('authToken', token);
    res.redirect('/profile'); // Redirect to profile after successful signin
});

app.get('/profile', (req, res) => {
    const token = req.cookies.authToken;
    if (!token) {
        return res.redirect('/signin'); // Redirect to signin if no token is found
    }

    jwt.verify(token, 'your_jwt_secret', async (err, decoded) => {
        if (err) {
            return res.redirect('/signin'); // Redirect to signin if the token is invalid
        }

        const user = await User.findById(decoded.userId);
        res.sendFile(path.join(__dirname, 'public', 'profile.html')); // Serve profile.html
    });
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
