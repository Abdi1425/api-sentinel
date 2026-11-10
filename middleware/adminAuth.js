
const requireAdmin = (req, res, next) => {
    // Check whether the administrator has an active session
    if (req.session && req.session.isAdmin === true) {
        return next();
    }

    // Reject requests without a valid administrator session
    return res.status(401).json({
        success: false,
        message: 'Unauthorized. Please log in as an administrator.'
    });
};

module.exports = requireAdmin;
