function chainedPromiseSql(req, res, next) {
    models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ""}' AND password = '${security.hash(req.body.password || "")}'`, { model: UserModel, plain: true })
        .then((authenticatedUser) => {
            res.send(authenticatedUser);
        }).catch((error) => {
            next(error);
        });
}

function nestedResolvedFile(req, res) {
    const file = req.params.file;
    res.sendFile(path.resolve("ftp/", file));
}
