// SQL injection across methods of a class: the request handler reads the
// untrusted id and passes it to a sibling method (this.runQuery) that runs the
// query. Class methods must be collected/analyzed, and `this.method(x)` must
// resolve to the sibling method for taint to flow.
var db = require("some-db");

class UserController {
  runQuery(uid) {
    return db.query("SELECT * FROM users WHERE id = " + uid); // sink
  }

  get(req, res) {
    var id = req.query.id;         // source
    res.send(this.runQuery(id));   // this.method() — cross-method call
  }
}

module.exports = UserController;
