function straightLine(req, res) {
    const userInput = req.query.name;
    const html = "<h1>" + userInput + "</h1>";
    res.send(html);
}

function killSemantics(req, res) {
    let x = req.query.name;
    x = "safe_value";
    res.send(x);
}

function branchMerge(req, res, flag) {
    let x;
    if (flag) {
        x = req.query.name;
    } else {
        x = "safe";
    }
    res.send(x);
}

function branchNoElse(req, res, flag) {
    let x = "default";
    if (flag) {
        x = req.query.name;
    }
    res.send(x);
}

function loopTaint(req, res) {
    let result = "";
    for (let i = 0; i < 10; i++) {
        result += req.query.name;
    }
    res.send(result);
}

function unknownCallPropagation(req, res) {
    const tainted = req.query.name;
    const result = helper(tainted);
    res.send(result);
}

function destructuringObject(req, res) {
    const { name, age } = req.body;
    res.send(name);
}

function destructuringArray(req, res) {
    const [first, second] = req.query.items;
    res.send(first);
}

function forOfLoop(req, res) {
    const items = req.body.list;
    for (const item of items) {
        res.send(item);
    }
}
