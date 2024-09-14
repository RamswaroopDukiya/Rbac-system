const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();

app.use(express.json());


const SECRET_KEY = 'your_secret_key';


const users = [];


const ROLES = {
    Admin: 'Admin',
    User: 'User',
    Guest: 'Guest'
};


function authenticateToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ message: 'No token provided' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
    });
}

function authorizeRoles(...roles) {
    return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
        return res.status(403).json({ message: 'Access forbidden: insufficient permissions' });
    }
    next();
    };
}



app.post('/register', async (req, res) => {
    const { username, password, role } = req.body;


    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
    username,
    password: hashedPassword,
    role: role || ROLES.Guest
    };

    users.push(newUser);
    res.status(201).json({ message: 'User registered successfully' });
});


app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = users.find(u => u.username === username);
    if (!user) return res.status(400).json({ message: 'User not found' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ message: 'Invalid password' });


    const token = jwt.sign({ username: user.username, role: user.role }, SECRET_KEY);
    res.json({ token });
});
