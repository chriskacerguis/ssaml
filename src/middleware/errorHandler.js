function errorHandler(err, req, res, _next) { res.status(err.status||500).send(err.message||'Error'); }
module.exports = { errorHandler };
