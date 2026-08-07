const serialize = require('node-serialize');

module.exports = (req, res) => {
  const blob = req.query.blob;
  serialize.unserialize(blob);

  // JSON.parse is data-only — it cannot produce a callable.
  const safe = JSON.parse(blob);
  res.json(safe);
};
