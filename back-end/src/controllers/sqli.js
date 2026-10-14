import prisma from '../database/client.js'
import { Prisma } from '@prisma/client'

const controller = {}

controller.login = async function(req, res) {
  const username = req.body?.username ?? ''
  const password = req.body?.password ?? ''

  try {
    // Consulta parametrizada para prevenir SQL Injection.
    const query = Prisma.sql`
      SELECT *
      FROM "User"
      WHERE username = ${username}
      AND password = ${password}
    `

    const users = await prisma.$queryRaw(query)

    if (users.length > 0) {
      return res.send({
        success: true,
        message: `Bem-vindo, ${username}!`,
        result: users
      })
    }

    return res.status(401).send({
      success: false,
      message: 'Login falhou!'
    })
  } catch (error) {
    console.error('Erro ao realizar login:', error)

    return res.status(500).send({
      success: false,
      message: 'Erro no servidor'
    })
  }
}

export default controller