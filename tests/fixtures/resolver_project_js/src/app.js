const { sanitize } = require("./utils");
const handler = require("./handler");

function main() {
    sanitize("<script>");
    handler.process();
}
