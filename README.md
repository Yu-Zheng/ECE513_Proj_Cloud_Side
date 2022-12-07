ECE513 Final Project (Server Side) - Team 3
======

This is a ECE513 final project server side code, and this project is a cloud heartrate monitor system for patient and physician. It allows patient easy to setup their devices to upload data to server, and physician can easy to check their reports.

**Team members:**

- Yu-Zheng Lin
- Chun-Lin Huang
- Alonso Montesinos


Require Modules
----------

| Module | Description |
| --- | --- |
| [Exrpress](https://expressjs.com/) | Web application framework |
| [mongoose](https://mongoosejs.com/) | MongoDB object modeling for node.js |
| [moment](https://momentjs.com/) | Parse, validate, manipulate, and display dates and times in JavaScript. |
| [http-errors](https://www.npmjs.com/package/http-errors) | Create HTTP errors |
| [cookie-parser](https://www.npmjs.com/package/cookie-parser) | Parse Cookie header and populate req.cookies with an object keyed by the cookie names. |
| [morgan](https://www.npmjs.com/package/morgan) | HTTP request logger middleware for node.js |
| [body-parser](https://www.npmjs.com/package/body-parser) | Node.js body parsing middleware. |

APIs
----------

Data API – Route: /api/\*

|APIs|Description|HTTP Method|
| :- | :- | :- |
|readAll|Read out all sensor data|GET|
|read\_patient\_data|Return all data from a patient|POST|
|weekly\_patient\_data|Return one week data from a patient|POST|
|Daily\_patient\_data|Return one day data from a patient|POST|
|Particle\_data|For receive data from Particle webhook|POST|

Patient API – Route: /patient/\*

|APIs|Description|HTTP Method|
| :- | :- | :- |
|create|Sing up a patient|POST|
|logIn|Log in to a patinet|POST|
|status|For check the authorization|GET|
|update\_device|Update a device name and device SN|POST|
|update\_info|Update the user info|POST|

Physician API – Route: /patient/\*

|APIs|Description|HTTP Method|
| :- | :- | :- |
|create|Sing up a physician|POST|
|logIn|Log in to a physician|POST|
|status|For check the authorization|GET|
|read\_all\_patient|Return all patient name and ID|GET|
|update\_info|Update the user info|POST|
