var express = require('express');
var router = express.Router();

var Patient = require("../models/patient");
const jwt = require("jwt-simple");
const bcrypt = require("bcryptjs");
const fs = require('fs');

// On AWS ec2, you can use to store the secret in a separate file. 
// The file should be stored outside of your code directory. 
// For encoding/decoding JWT
const secret = fs.readFileSync(__dirname + '/../keys/jwtkey').toString();



router.post("/create", function (req, res) {
    Patient.findOne({ Email: req.body.email }, function (err, patient) {
        if (err) res.status(401).json({ success: false, err: err });
        else if (patient) {
            console.log(patient);
            res.status(401).json({ success: false, msg: "This email already used" });
        }
        else {
            const passwordHash = bcrypt.hashSync(req.body.password, 10);
            const newPatient = new Patient({
                First_name: req.body.First_name,
                Last_name: req.body.Last_name,
                Email: req.body.Email,
                password: passwordHash,
            });
            newPatient.save(function (err, patient) {
                if (err) {
                    res.status(400).send(err);
                }
                else {
                    let msgStr = `patient (${req.body.First_name}) info has been saved.`;
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
    Patient.findOne({ Email: req.body.email }, function (err, patient) {
        if (err) {
            res.status(400).send(err);
        }
        else if (!patient) {
            // Username not in the database
            res.status(401).json({ error: "Login failure!!" });
        }
        else {
            if (bcrypt.compareSync(req.body.password, patient.password)) {
                const token = jwt.encode({ Email: patient.Email }, secret);
                //update user's last access time
                patient.lastAccess = new Date();
                patient.save((err, patient) => {
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
        console.log(decoded.Email)
        // Send back email and last access
        Patient.find({ Email: decoded.Email }, "First_name Last_name Email deviceID lastAccess physician device_name device_sn", function (err, users) {
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



router.post("/update_device", function (req, res) {
    Patient.findOneAndUpdate({ _id: req.body._id }, { "$set": { "device_name": req.body.device_name, "device_sn": req.body.device_sn } }, function (err, doc) {
        if (err) {
            let msgStr = `Something wrong....`;
            res.status(201).json({ message: msgStr, err: err });
        }
        else {
            let msgStr;
            if (doc == null) {
                msgStr = `Patient (Device SN: ${req.body.device_sn}) info does not exist in DB.`;
            }
            else {
                msgStr = `Patient (Device SN: ${req.body.device_sn}) info has been updated.`;
            }

            res.status(201).json({ message: msgStr });
        }
    })
});

router.post("/update_info", function (req, res) {
    Patient.findOneAndUpdate({ _id: req.body._id }, { "$set": { "First_name": req.body.First_name, "Last_name": req.body.Last_name, "Email": req.body.Email, "physician": req.body.physician } }, function (err, doc) {
        if (err) {
            let msgStr = `Something wrong....`;
            res.status(201).json({ message: msgStr, err: err });
        }
        else {
            let msgStr;
            if (doc == null) {
                msgStr = `Patient info does not exist in DB.`;
            }
            else {
                msgStr = `Patient info has been updated.`;
            }

            res.status(201).json({ message: msgStr });
        }
    })
});

module.exports = router;