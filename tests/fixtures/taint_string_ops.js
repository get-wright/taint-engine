function templateLiteralPropagation(req, res) {
    const userInput = req.query.name;
    const html = `<h1>${userInput}</h1>`;
    res.send(html);
}

function concatPropagation(req, res) {
    const userInput = req.query.name;
    const html = "<h1>" + userInput + "</h1>";
    res.send(html);
}
