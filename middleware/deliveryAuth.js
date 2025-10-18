const jwt = require('jsonwebtoken');
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET;

module.exports = function(req, res, next) {
    const token = req.header('x-auth-token');

    if (!token) {
        return res.status(401).json({ msg: 'No token, authorization denied' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        // Add the staff payload from the token to the request object
        req.staff = decoded.staff;
        next();
    } catch (err) {
        res.status(401).json({ msg: 'Token is not valid' });
    }
};