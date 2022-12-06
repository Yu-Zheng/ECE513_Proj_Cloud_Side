var express = require('express');
var router = express.Router();
var Physician = require("../models/physician");
var Patient = require("../models/patient");
const jwt = require("jwt-simple");
const bcrypt = require("bcryptjs");
const fs = require('fs');

// On AWS ec2, you can use to store the secret in a separate file. 
// The file should be stored outside of your code directory. 
// For encoding/decoding JWT
const secret = fs.readFileSync(__dirname + '/../keys/jwtkey').toString();


router.post("/create", function (req, res) {
    Physician.findOne({ Email: req.body.email }, function (err, customer) {
        if (err) res.status(401).json({ success: false, err: err });
        else if (customer) {
            res.status(401).json({ success: false, msg: "This email already used" });
        }
        else {
            const passwordHash = bcrypt.hashSync(req.body.password, 10);
            const newPhysician = new Physician({
                First_name: req.body.First_name,
                Last_name: req.body.Last_name,
                Email: req.body.Email,
                password: passwordHash,
            });
            newPhysician.save(function (err, Physician) {
                if (err) {
                    res.status(400).send(err);
                }
                else {
                    let msgStr = `Physician (${req.body.First_name}) info has been saved.`;
                    res.status(201).json({ message: msgStr });
                    console.log(msgStr);
                }
            });
        }
    });
});


router.post("/logIn", function (req, res) {
    if (!req.body.email || !req.body.password) {
        res.status(401).json({ error: "Missing email and/or password" });
        return;
    }
    // Get user from the database
    Physician.findOne({ Email: req.body.email }, function (err, Physician) {
        if (err) {
            res.status(400).send(err);
        }
        else if (!Physician) {
            // Username not in the database
            res.status(401).json({ error: "Login failure!!" });
        }
        else {
            if (bcrypt.compareSync(req.body.password, Physician.password)) {
                const token = jwt.encode({ Email: Physician.Email }, secret);
                //update user's last access time
                Physician.lastAccess = new Date();
                Physician.save((err, Physician) => {
                    console.log("User's LastAccess has been update.");
                });
                // Send back a token that contains the user's username
                res.status(201).json({ success: true, token: token, msg: "Login success" });
            }
            else {
                res.status(401).json({ success: false, msg: "Email or password invalid." });
            }
        }
    });
});


router.get("/status", function (req, res) {
    // See if the X-Auth header is set
    if (!req.headers["x-auth"]) {
        return res.status(401).json({ success: false, msg: "Missing X-Auth header" });
    }

    // X-Auth should contain the token 
    const token = req.headers["x-auth"];
    try {
        const decoded = jwt.decode(token, secret);
        // Send back email and last access
        Physician.find({ Email: decoded.Email }, "First_name Last_name Email deviceID lastAccess physician device_name device_sn", function (err, users) {
            if (err) {
                res.status(400).json({ success: false, message: "Error contacting DB. Please contact support." });
            }
            else {
                res.status(200).json(users);
            }
        });
    }
    catch (ex) {
        res.status(401).json({ success: false, message: "Invalid JWT" });
    }
});


router.get('/read_all_patient', function (req, res) {
    Patient.find({}, "First_name device_sn", function (err, docs) {
        if (err) {
            let msgStr = `Something wrong....`;
            res.status(201).json({ message: msgStr });
        }
        else {
            res.status(201).json(docs);
        }
    });
});

router.post("/update_info", function (req, res) {
    Physician.findOneAndUpdate({ _id: req.body._id }, { "$set": { "First_name": req.body.First_name, "Last_name": req.body.Last_name, "Email": req.body.Email, "physician": req.body.physician } }, function (err, doc) {
        if (err) {
            let msgStr = `Something wrong....`;
            res.status(201).json({ message: msgStr, err: err });
        }
        else {
            let msgStr;
            if (doc == null) {
                msgStr = `Physician info does not exist in DB.`;
            }
            else {
                msgStr = `Physician info has been updated.`;
            }

            res.status(201).json({ message: msgStr });
        }
    })
});

module.exports = router;