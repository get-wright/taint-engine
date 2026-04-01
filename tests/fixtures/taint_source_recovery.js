// Line numbers are critical for tests — do not add/remove lines without updating tests

function destructuredRedirect(req, res) {
    const { query } = req;
    const toUrl = query.to;
    res.redirect(toUrl);
}

function destructuredFileServe(req, res) {
    const { params } = req;
    const file = params.file;
    res.sendFile(file);
}

function directMemberSink(req, res) {
    res.redirect(req.query.url);
}
