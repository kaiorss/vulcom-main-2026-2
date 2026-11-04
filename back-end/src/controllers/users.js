import prisma from '../database/client.js'
import jwt from 'jsonwebtoken'
import argon2 from 'argon2'

const argon2Options = {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1
}

const controller = {}

controller.create = async function(req, res) {
  try {
    const data = { ...req.body }
    if(data.password && !data.password.startsWith('$argon2')) {
      data.password = await argon2.hash(
        data.password,
        argon2Options
      )
    }

    await prisma.user.create({
      data
    })

    res.status(201).end()
  }
  catch(error) {
    console.error(error)
    res.status(500).end()
  }
}

controller.retrieveAll = async function(req, res) {
  try {
    const result = await prisma.user.findMany()

    res.send(result)
  }
  catch(error) {
    console.error(error)
    res.status(500).end()
  }
}

controller.retrieveOne = async function(req, res) {
  try {
    const result = await prisma.user.findUnique({
      where: { id: Number(req.params.id) }
    })

    if(result) res.send(result)
    else res.status(404).end()
  }
  catch(error) {
    console.error(error)
    res.status(500).end()
  }
}

controller.update = async function(req, res) {
  try {
    const data = { ...req.body }

    if(data.password) {
      if(!data.password.startsWith('$argon2')) {
        data.password = await argon2.hash(
          data.password,
          argon2Options
        )
      }
    } else {
      delete data.password
    }

    const result = await prisma.user.update({
      where: { id: Number(req.params.id) },
      data
    })

    if(result) res.status(204).end()
    else res.status(404).end()
  }
  catch(error) {
    console.error(error)
    res.status(500).end()
  }
}

controller.delete = async function(req, res) {
  try {
    await prisma.user.delete({
      where: { id: Number(req.params.id) }
    })

    res.status(204).end()
  }
  catch(error) {
    if(error?.code === 'P2025') {
      res.status(404).end()
    }
    else {
      console.error(error)
      res.status(500).end()
    }
  }
}

controller.login = async function(req, res) {
  try {
    const user = await prisma.user.findFirst({
      where: {
        OR: [
          { username: req.body?.username },
          { email: req.body?.email }
        ]
      }
    })

    if(!user) return res.status(401).end()

    let passwordIsValid = false
    try {
      if(user.password.startsWith('$argon2')) {
        passwordIsValid = await argon2.verify(
          user.password,
          req.body?.password
        )
      } else {
        passwordIsValid = user.password === req.body?.password
        if(passwordIsValid) {
          const newHash = await argon2.hash(req.body.password, argon2Options)
          await prisma.user.update({
            where: { id: user.id },
            data: { password: newHash }
          })
        }
      }
    } catch (e) {
      passwordIsValid = user.password === req.body?.password
    }

    if(!passwordIsValid) return res.status(401).end()

    const token = jwt.sign(
      user,
      process.env.TOKEN_SECRET,
      { expiresIn: '24h' }
    )

    res.cookie(process.env.AUTH_COOKIE_NAME, token, {
      httpOnly: true,
      secure: true,
      sameSite: 'None',
      path: '/',
      maxAge: 24 * 60 * 60 * 100
    })

    res.send({token, user})
  }
  catch(error) {
    console.error(error)
    res.status(500).end()
  }
}

controller.me = function(req, res) {
  res.send(req?.authUser)
}

export default controller