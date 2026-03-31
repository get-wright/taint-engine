function sanitize(input) {
    return input.replace(/</g, "&lt;");
}

module.exports = { sanitize };
