var express = require('express');
var bodyParser = require('body-parser');
var mysql = require('mysql');
var cors = require('cors');
var app = express();
let map = new Map();

app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(bodyParser.json());
app.use(cors());

const database = 'mobile';

var conn = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'root',
    database: database
});

conn.connect(function (err) {
    if (err) {
        console.log('Error connecting to DB');
        return;
    }
    console.log('DB Connection established');
});

app.post('/api/account/create', function (req, res) {
    conn.query('insert into users(username, password, fullName) values(?, ?, ?)', [req.body.username, req.body.password, req.body.fullName], function (error, result) {
        if (error || result.affectedRows == 0) {
            res.write('false');
        } else {
            res.write('true');
        }
        res.end();
    });
});

app.post('/api/account/login', function (req, res) {
    conn.query('select * from users where username = ? and password = ?', [req.body.username, req.body.password], function (error, rows) {
        if (rows != null && rows.length > 0) {
            const token = randomIdGenerator();
            // console.log(token);
            map.set(token, req.body.username);
            res.write(token);
        } else {
            res.write('false');
        }
        res.end();
    });
});

app.put('/api/account/update', function (req, res) {
    if (req.body.token !== 'undefined' && req.body.username !== 'undefined' && map.get(req.body.token) === req.body.username) {
        conn.query('update users set password = ?, fullName = ? where username = ?', [req.body.password, req.body.fullName, req.body.username], function (error, rows) {
            if (error || rows.affectedRows == 0) {
                res.write('false');
            } else {
                res.write('true');
            }
            res.end();
        });
    }
});

app.get('/api/vulnerability/findall', function (req, res) {
    if ((req.header.hasOwnProperty('token') && req.header.hasOwnProperty('username') && map.get(req.header.token) === req.header.username) ||
        (req.body.token !== 'undefined' && req.body.username !== 'undefined' && map.get(req.body.token) === req.body.username)) {
        conn.query('select * from vulnerabilities', function (err, rows) {
            res.json(rows);
        });
    } else {
        console.log("invalid token")
    }
});

app.post('/api/vulnerability', function (req, res) {
    if (req.body.hasOwnProperty('token') && req.body.hasOwnProperty('username') && map.get(req.body.token) === req.body.username) {
        conn.query('insert into vulnerabilities(severity, type, targetIP, port) values(?, ?, ?, ?)', [req.body.severity, req.body.type, req.body.targetIP, req.body.port], function (err, rows) {
            res.json(rows);
        });
    } else {
        console.log("invalid token")
    }
});

app.get('/api/vulnerability/empty', function (req, res) {
    if (req.body.token !== 'undefined' && req.body.username !== 'undefined' && map.get(req.body.token) === req.body.username) {
        conn.query('delete from vulnerabilities', function (err, rows) {
            res.json(rows);
        })
    } else {
        console.log("invalid token")
    }
});

app.listen(3000);

function uniqueId() {
    const firstItem = {
        value: "0"
    };
    /*length can be increased for lists with more items.*/
    let counter = "12345678".split('')
        .reduce((acc, curValue, curIndex, arr) => {
            const curObj = {};
            curObj.value = curValue;
            curObj.prev = acc;

            return curObj;
        }, firstItem);
    firstItem.prev = counter;

    return function () {
        let now = Date.now();
        if (typeof performance === "object" && typeof performance.now === "function") {
            now = performance.now().toString().replace('.', '');
        }
        counter = counter.prev;
        return `${now}${Math.random().toString(5).substr(2)}${counter.value}`;
    }
}

const randomIdGenerator = uniqueId();
