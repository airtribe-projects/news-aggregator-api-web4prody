require('dotenv').config();

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

// This value comes from .env locally or from an environment variable in deployment.
const JWT_SECRET = process.env.JWT_SECRET || 'development-only-secret-change-in-production';

// Temporary in-memory storage. Data resets when the server restarts.
const users = [];

const newsArticles = [
    {
        id: 1,
        title: 'New superhero movie announced',
        category: 'movies'
    },
    {
        id: 2,
        title: 'Classic comic series receives a new edition',
        category: 'comics'
    },
    {
        id: 3,
        title: 'Major game release scheduled for this year',
        category: 'games'
    },
    {
        id: 4,
        title: 'Technology industry weekly update',
        category: 'technology'
    }
];

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

function authenticateToken(req, res, next) {
    const authorizationHeader = req.headers.authorization;

    if (!authorizationHeader || !authorizationHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Authentication token is required' });
    }

    const token = authorizationHeader.split(' ')[1];

    try {
        const decodedToken = jwt.verify(token, JWT_SECRET);
        const user = users.find((currentUser) => currentUser.id === decodedToken.id);

        if (!user) {
            return res.status(401).json({ message: 'User not found' });
        }

        req.user = user;
        next();
    } catch (error) {
        return res.status(401).json({ message: 'Invalid or expired token' });
    }
}

// Create a user account.
app.post('/users/signup', async (req, res) => {
    const { name, email, password, preferences } = req.body;

    if (
        typeof name !== 'string' ||
        !name.trim() ||
        typeof email !== 'string' ||
        !email.trim() ||
        typeof password !== 'string' ||
        !password ||
        !Array.isArray(preferences)
    ) {
        return res.status(400).json({
            message: 'Name, email, password, and preferences are required'
        });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const existingUser = users.find((user) => user.email === normalizedEmail);

    if (existingUser) {
        return res.status(409).json({ message: 'An account with this email already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    users.push({
        id: users.length + 1,
        name: name.trim(),
        email: normalizedEmail,
        passwordHash,
        preferences
    });

    return res.status(200).json({ message: 'User created successfully' });
});

// Log in and receive a JWT.
app.post('/users/login', async (req, res) => {
    const { email, password } = req.body;

    if (typeof email !== 'string' || typeof password !== 'string') {
        return res.status(400).json({ message: 'Email and password are required' });
    }

    const user = users.find((currentUser) => currentUser.email === email.trim().toLowerCase());

    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
        return res.status(401).json({ message: 'Invalid email or password' });
    }

    const token = jwt.sign(
        { id: user.id, email: user.email },
        JWT_SECRET,
        { expiresIn: '1h' }
    );

    return res.status(200).json({ token });
});

// Get the signed-in user's preferences.
app.get('/users/preferences', authenticateToken, (req, res) => {
    return res.status(200).json({ preferences: req.user.preferences });
});

// Replace the signed-in user's preferences.
app.put('/users/preferences', authenticateToken, (req, res) => {
    const { preferences } = req.body;

    if (!Array.isArray(preferences)) {
        return res.status(400).json({ message: 'Preferences must be an array' });
    }

    req.user.preferences = preferences;

    return res.status(200).json({
        message: 'Preferences updated successfully',
        preferences: req.user.preferences
    });
});

// Return news matching the signed-in user's saved preferences.
app.get('/news', authenticateToken, (req, res) => {
    const preferredNews = newsArticles.filter((article) =>
        req.user.preferences.includes(article.category)
    );

    return res.status(200).json({ news: preferredNews });
});

if (require.main === module) {
    app.listen(port, (error) => {
        if (error) {
            console.error('Unable to start server:', error);
            return;
        }

        console.log(`Server is listening on ${port}`);
    });
}

module.exports = app;
