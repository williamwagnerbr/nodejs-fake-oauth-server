const express = require('express')
const path = require('path')
const fs = require('fs')
const uuid = require('uuid/v4')
const rp = require('request-promise')
const bodyParser = require('body-parser')
const port = 9014
const server_addr = `http://localhost:${port}`
const app = express()

const memoryDatabase = {
  clients: require('./config/consumers.json'),
  users: require('./config/users.json'),
  requests: {},
  authz: {},
  tokens: {},
  access_tokens: {},
  users_notes: {}
}

var utils = {
  authConsumer: function (req, res, next) {
    var data = req.body
    var found = null

    if (!data.consumer_key) {
      return res.status(400).send('Param "consumer_key" not defined')
    }

    if (!data.consumer_secret) {
      return res.status(400).send('Param "consumer_secret" not defined')
    }

    memoryDatabase.clients.map((client) => {
      if ((client.consumer_key === data.consumer_key) && (client.consumer_secret === data.consumer_secret)) {
        found = client
      }
    })

    if (!found) {
      return res.status(400).send('Invalid client "key" or "secret"')
    }

    req.consumer = found
    next()
  },
  authApi: function (req, res, next) {
    var auth = req.header('authorization')
    if (!auth) {
      return res.status(401).send('Authorization header not found')
    }

    if (!auth.startsWith('Bearer ')) {
      return res.status(401).send('Invalid authorization method')
    }

    var token = auth.substr(7)

    if (!memoryDatabase.access_tokens[token]) {
      return res.status(401).send('Access denied')
    }

    accessToken = memoryDatabase.access_tokens[token]
    req.user = accessToken.user
    req.consumer = accessToken.client
    next()
  }
}

/** OAUTH **/
app.post('/oauth/request_token', bodyParser.json(), utils.authConsumer, function (req, res, next) {
  var data = req.body
  var id = uuid()

  memoryDatabase.requests[id] = {
    client: req.consumer
  }

  res.send({
    url: `${server_addr}/oauth/login/${id}`
  })
})

app.post('/oauth/authorize', bodyParser.json(), utils.authConsumer, function (req, res, next) {
  var data = req.body
  var consumer = req.consumer

  if (!data.token) {
    return res.status(400).send('Param "token" not defined')
  }

  if (!memoryDatabase.tokens[data.token]) {
    return res.status(400).send('Invalid token')
  }

  var token = memoryDatabase.tokens[data.token]
  var client = token.authz.request.client

  if (client.consumer_key !== consumer.consumer_key) {
    return res.status(400).send('Client "consumer_key" mismatch')
  }

  if (client.consumer_secret !== consumer.consumer_secret) {
    return res.status(400).send('Client "consumer_secret" mismatch')
  }

  if (token.taken) {
    return res.status(400).send('Token already taken')
  }

  var accessTokenId = uuid()
  memoryDatabase.tokens[data.token].taken = true
  memoryDatabase.access_tokens[accessTokenId] = {
    user: token.authz.user,
    client: client
  }

  res.send({
    access_token: accessTokenId
  })
})

app.get('/oauth/login/:code', function (req, res, next) {
  if (!memoryDatabase.requests[req.params.code]) {
    return res.status(404).send('Invalid login code')
  }

  var request = memoryDatabase.requests[req.params.code]
  var accounts = memoryDatabase.users.map((user, index) => {
    var authzId = uuid()

    memoryDatabase.authz[authzId] = {
      request: request,
      user: user
    }

    return {
      user: user,
      actions: {
        approve_url: `${server_addr}/bot/${authzId}/resolve`,
        reject_url: `${server_addr}/bot/${authzId}/reject`
      }
    }
  })

  res.send(accounts)
})

/** BOT ACTIONS **/
app.get('/bot/:code/resolve', function (req, res, next) {
  if (!memoryDatabase.authz[req.params.code]) {
    return res.status(404).send('Invalid authz code')
  }

  var authz = memoryDatabase.authz[req.params.code]
  var id = uuid()

  memoryDatabase.tokens[id] = {
    id: id,
    authz: authz,
    taken: false
  }

  var requestParams = {
    uri: authz.request.client.callbacks['new-authorization'],
    json: {
      token: id
    }    
  }

  rp.post(requestParams)
  .then(() => {
    res.send('Ok')
  })
  .catch((err) => {
    res.status(500).send(err.toString())
  })
})

app.get('/bot/:code/reject', function (req, res, next) {
  res.status(500).send('Not implemented yet')
})

/** CALLBACKS **/
app.post('/callbacks/new-authorization', bodyParser.json(), function (req, res, next) {
  console.log('New authorization', JSON.stringify(req.body, null, 2))
  res.send('Ok')
})

app.post('/callbacks/rem-authorization', bodyParser.json(), function (req, res, next) {
  console.log('Remove authorization', JSON.stringify(req.body, null, 2))
  res.send('Ok')
})

/** API **/
app.get('/api/me', utils.authApi, bodyParser.json(), function (req, res, next) {
  res.send({
    user: req.user,
    consumer: req.consumer
  })
})

app.get('/api/notes', utils.authApi, bodyParser.json(), function (req, res, next) {
  if (!memoryDatabase.user_notes[req.user.id]) {
    res.send([])
  }
  res.send(memoryDatabase.user_notes[req.user.id])
})

app.post('/api/notes', utils.authApi, bodyParser.json(), function (req, res, next) {
  var id = uuid()

  var note = {
    id: id,
    author_id: req.user.id,
    message: req.body.message
  }

  if (!memoryDatabase.user_notes[req.user.id]) {
    memoryDatabase.user_notes[req.user.id] = []
  }

  memoryDatabase.user_notes[req.user.id][id] = note
  res.send(note)
})

app.get('/api/notes/:id', utils.authApi, bodyParser.json(), function (req, res, next) {
  if (!memoryDatabase.user_notes[req.user.id]) {
    return res.status(404).send('Note not found')
  }

  if (!memoryDatabase.user_notes[req.user.id][req.params.id]) {
    return res.status(404).send('Note not found')
  }

  var note = memoryDatabase.user_notes[req.user.id][req.params.id]
  res.send(note)
})

app.listen(port)
console.log(`App running on port http://localhost:${port}/`)
