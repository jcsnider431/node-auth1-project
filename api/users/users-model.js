const db = require("../../database/connection.js");

/**
  resolves to an ARRAY with all users, each user having { user_id, username }
 */
  module.exports = {
    add,
    find,
    findBy,
    findById,
  };

function find() {
  return db("user").select("id", "username").orderBy("id");
}

/**
  resolves to an ARRAY with all users that match the filter condition
 */
function findBy(filter) {
  return db("users").where(filter).orderBy("id");
}

/**
  resolves to the user { user_id, username } with the given user_id
 */
function findById(user_id) {
  return db("users").where({ user_id }).first();
}

/**
  resolves to the newly inserted user { user_id, username }
 */
async function add(user) {
  const [id] = await db("users").insert(user, "id");
  return findById(id);
}

// Don't forget to add these to the `exports` object so they can be required in other modules
