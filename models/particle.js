const db = require("../db");

const HR_Recording = db.model("HR_Recording", {
    deviceID:    {type: String},
    HR:  {type: Number},
    SPO2: {type: Number},
    published_at: { type: Date, default: Date.now },
 });

module.exports = HR_Recording;