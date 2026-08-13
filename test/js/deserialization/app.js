const serialize = require('node-serialize');

module.exports = (req, res) => {
  const blob = req.query.blob;
  serialize.unserialize(blob);

  serialize.unserialize(JSON.parse(blob));
  res.end('ok');
};
