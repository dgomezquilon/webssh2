// app.js

let path = require('path')
// configPath = path.join(__dirname, 'config.json')
let nodeRoot = path.dirname(require.main.filename)
let configPath = path.join(nodeRoot, 'config.json')
let publicPath = path.join(nodeRoot, 'client', 'public')
console.log('WebSSH2 service reading config from: ' + configPath)
let config = require('read-config')(configPath)
let express = require('express')
let logger = require('morgan')
let session = require('express-session')({
  secret: config.session.secret,
  name: config.session.name,
  resave: true,
  saveUninitialized: false,
  unset: 'destroy'
})
let app = express()
let compression = require('compression')
let server = require('http').Server(app)
let myutil = require('./util')
let validator = require('validator')
let io = require('socket.io')(server, {serveClient: false})
let socket = require('./socket')
let expressOptions = require('./expressOptions')

// External connection
let bodyParser = require('body-parser')
const uuidv4 = require('uuid/v4')
const low = require('lowdb')
const MemoryAdapter = require('lowdb/adapters/Memory')
const adapter = new MemoryAdapter()
let db = low(adapter)
db.defaults({connections: []}).write()

// express
app.use(compression({level: 9}))
app.use(session)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({extended: false}))
if (config.accesslog) app.use(logger('common'))
app.disable('x-powered-by')

// static files
app.use(express.static(publicPath, expressOptions))

// LowDB
app.use(function (req, res, next) {
  req.db = db
  next()
})

app.get('/connect/:accessToken', function (req, res) {
  let connection = req.db.get('connections').find({accessToken: req.params.accessToken}).value()
  if (!connection) {
    res.status(404).send('Sorry can\'t find that!')
  } else {
    req.db.get('connections').remove({accessToken: req.params.accessToken}).write() // Remove connection
    // Check if expired
    let date = new Date().getTime()
    if (date > connection.expiresAt) {
      res.status(404).send('Sorry can\'t find that!')
      return
    }
    req.session.ssh = {
      host: connection.address,
      port: connection.port,
      username: connection.username,
      passphrase: connection.passphrase,
      privateKey: connection.privateKey,
      header: {
        name: req.query.header || config.header.text,
        background: req.query.headerBackground || config.header.background
      },
      algorithms: config.algorithms,
      keepaliveInterval: config.ssh.keepaliveInterval,
      keepaliveCountMax: config.ssh.keepaliveCountMax,
      term: (/^(([a-z]|[A-Z]|[0-9]|[!^(){}\-_~])+)?\w$/.test(req.query.sshterm) &&
        req.query.sshterm) || config.ssh.term,
      terminal: {
        cursorBlink: (validator.isBoolean(req.query.cursorBlink + '') ? myutil.parseBool(req.query.cursorBlink) : config.terminal.cursorBlink),
        scrollback: (validator.isInt(req.query.scrollback + '', {
          min: 1,
          max: 200000
        }) && req.query.scrollback) ? req.query.scrollback : config.terminal.scrollback,
        tabStopWidth: (validator.isInt(req.query.tabStopWidth + '', {
          min: 1,
          max: 100
        }) && req.query.tabStopWidth) ? req.query.tabStopWidth : config.terminal.tabStopWidth,
        bellStyle: ((req.query.bellStyle) && (['sound', 'none'].indexOf(req.query.bellStyle) > -1)) ? req.query.bellStyle : config.terminal.bellStyle
      },
      allowreplay: (validator.isBoolean(req.headers.allowreplay + '') ? myutil.parseBool(req.headers.allowreplay) : false),
      mrhsession: ((validator.isAlphanumeric(req.headers.mrhsession + '') && req.headers.mrhsession) ? req.headers.mrhsession : 'none'),
      serverlog: {
        client: config.serverlog.client || false,
        server: config.serverlog.server || false
      },
      readyTimeout: (validator.isInt(req.query.readyTimeout + '', {min: 1, max: 300000}) &&
        req.query.readyTimeout) || config.ssh.readyTimeout
    }
    res.sendFile(path.join(path.join(publicPath, 'client.htm')))
  }
})

app.post('/authentication', function (req, res) {
  let data = req.body
  if (data.address && data.port && data.username && data.privateKey && data.token) {
    let date = new Date()
    date.setSeconds(date.getSeconds() + config.connections.expires)
    let exists = req.db.get('connections').find({address: data.address, token: data.token}).value()
    let values = Object.assign({}, data, {
      accessToken: uuidv4(),
      expiresAt: date.getTime()
    })
    if (exists) {
      req.db.get('connections').find({address: exists.address, token: exists.token}).assign(values).write()
    } else {
      req.db.get('connections').push(values).write()
    }
    res.send(values)
  } else {
    res.status(500).send('Sorry can\'t find that!')
  }
})

// express error handling
app.use(function (req, res, next) {
  res.status(404).send('Sorry can\'t find that!')
})

app.use(function (err, req, res, next) {
  console.error(err.stack)
  res.status(500).send('Something broke!')
})

// socket.io
// expose express session with socket.request.session
io.use(function (socket, next) {
  (socket.request.res) ? session(socket.request, socket.request.res, next)
    : next(next)
})

// bring up socket
io.on('connection', socket)

module.exports = {server: server, config: config}
