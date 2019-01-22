const bcrypt = require("bcryptjs");

exports.seed = function(knex, Promise) {
  // Deletes ALL existing entries
  return knex("users")
    .truncate()
    .then(function() {
      // Inserts seed entries
      return knex("users").insert([
        { username: "joseph", password: bcrypt.hashSync("pass", 12) },
        { username: "david", password: bcrypt.hashSync("pass", 12) },
        { username: "blake", password: bcrypt.hashSync("pass", 12) },
        { username: "nick", password: bcrypt.hashSync("pass", 12) }
      ]);
    });
};
