const {model} = require("mongoose");

const {UserSchema} = require("../schemas/UsersSchema");

const UsersModel = new model("user", UserSchema);

module.exports = {UsersModel};