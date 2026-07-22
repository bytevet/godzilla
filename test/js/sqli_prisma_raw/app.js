// Express + Prisma: SQL injection via $queryRawUnsafe.
//
// GET /user?name=<name> concatenates an untrusted query parameter into a plain
// SQL string handed to Prisma's $queryRawUnsafe -- the raw escape hatch that,
// unlike the safe tagged-template $queryRaw`...` form, does no parameterization.

var express = require("express");
var { PrismaClient } = require("@prisma/client");
var prisma = new PrismaClient();
var app = express();

function handleUser(req, res) {
  var name = req.query.name;
  var sql = "SELECT * FROM users WHERE name = '" + name + "'";
  prisma.$queryRawUnsafe(sql).then(function (rows) {
    res.send(rows);
  });
}

app.get("/user", handleUser);

module.exports = app;
