function vulnerableXss(req, res) {
    const userInput = req.query.name;
    const html = "<h1>" + userInput + "</h1>";
    res.send(html);
}

function sanitizedXss(req, res) {
    const userInput = req.query.name;
    const safe = escapeHtml(userInput);
    const html = "<h1>" + safe + "</h1>";
    res.send(html);
}

function multilineCall(req, res) {
    const userInput = req.query.search;
    const result = fetch(
        "/api/search?q=" + userInput,
        { method: "GET" }
    );
}

function innerHtmlSink(data) {
    const content = data.message;
    document.getElementById("output").innerHTML = content;
}

function innerHtmlSanitized(data) {
    const content = escapeHtml(data.message);
    document.getElementById("output").innerHTML = content;
}

function hrefSink(userUrl) {
    const link = document.getElementById("link");
    link.href = userUrl;
}

function hardcodedInnerHtml() {
    const svg = '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="5"/></svg>';
    document.getElementById("icon").innerHTML = svg;
}
