const jwt = require('jsonwebtoken');
require('dotenv').config(); // Ensure environment variables are loaded

const JWT_SECRET = process.env.JWT_SECRET;

module.exports = function(req, res, next) {
    // Get token from the 'x-auth-token' header
    const token = req.header('x-auth-token');

    // Check if no token is present
    if (!token) {
        return res.status(401).json({ msg: 'No token, authorization denied' });
    }

    // Verify the token
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // Add the student payload from the token to the request object
        req.student = decoded.student;
        next(); // Proceed to the next middleware or route handler
    } catch (err) {
        res.status(401).json({ msg: 'Token is not valid' });
    }
};