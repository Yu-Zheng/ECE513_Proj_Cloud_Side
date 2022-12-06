const db = require("../db");

const physicianSchema = new db.Schema({
    First_name:      String,
    Last_name:     String,
    Email: String,
    password: String,
 });


const Physician = db.model("Physician", physicianSchema);

module.exports = Physician;