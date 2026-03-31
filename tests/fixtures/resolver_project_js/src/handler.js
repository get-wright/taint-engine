const { sanitize } = require("./utils/helper");

function process() {
    return sanitize(input);
}

module.exports = { process };
