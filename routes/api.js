var express = require('express');
var moment = require('moment');
var router = express.Router();
var PARTICLE_DB = require("../models/particle");


router.get('/readAll', function (req, res) {
   PARTICLE_DB.find(function (err, docs) {
      if (err) {
         let msgStr = `Something wrong....`;
         res.status(201).json({ message: msgStr });
      }
      else {
         res.status(201).json(docs);
      }
   });
});

router.post('/read_patient_data', function (req, res) {
   PARTICLE_DB.find({ deviceID: req.body.device_sn }, function (err, docs) {
      if (err) {
         let msgStr = `Something wrong....`;
         res.status(201).json({ message: msgStr });
      }
      else {
         res.status(201).json(docs);
      }
   });
});

router.post('/weekly_patient_data', function (req, res) {
   const end = moment(req.body.current_date).startOf('day').toDate();
   const start = moment(req.body.current_date).startOf('day').subtract(7, 'day').toDate();
   console.log(end);
   console.log(start);

   PARTICLE_DB.find({
      $and: [
         {
            deviceID: req.body.device_sn
         },
         {
            createdAt: { $gte: start, $lt: end }
         }
      ]
   }, function (err, docs) {
      if (err) {
         let msgStr = `Something wrong....`;
         res.status(201).json({ message: msgStr });
      }
      else {
         res.status(201).json(docs);
      }
   });
});

router.post('/daily_patient_data', function (req, res) {
   const end = moment(req.body.current_date).startOf('day').toDate();
   const start = moment(req.body.current_date).startOf('day').subtract(1, 'day').toDate();
   console.log(end);
   console.log(start);

   PARTICLE_DB.find({
      $and: [
         {
            deviceID: req.body.device_sn
         },
         {
            createdAt: { $gte: start, $lt: end }
         }
      ]
   }, function (err, docs) {
      if (err) {
         let msgStr = `Something wrong....`;
         res.status(201).json({ message: msgStr });
      }
      else {
         res.status(201).json(docs);
      }
   });
});

router.post("/particle_data", function (req, res) {
   res.status(200);
   console.log(req.body);

   let HR_Value;
   let SPO2_Value;

   if (req.body.HR === "-999") {
      HR_Value = 0;
   } else {
      HR_Value = req.body.HR;
   }

   if (req.body.SPO2 === "-999") {
      SPO2_Value = 0;
   } else {
      SPO2_Value = req.body.SPO2;
   }

   const newParticle = new PARTICLE_DB({
      deviceID: req.body.coreid,
      HR: HR_Value,
      SPO2: SPO2_Value,
      published_at: req.body.published_at,
   });
   newParticle.save(function (err, deviceID) {
      if (err) {
         var errormsg = { "error": "zip and airQuality are required." }
         res.status(400).send(errormsg);
      }
      else {
         var msg = { "response": "Data recorded." }
         res.status(201).json(msg);
      }
   });
});

module.exports = router;