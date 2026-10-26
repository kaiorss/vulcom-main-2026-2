
import prisma from '../database/client.js'

const controller = {}

controller.retrieveComments = async function(req, res) {
  try {
    const comments = await prisma.xssComment.findMany({
      orderBy: { id: 'asc' }
    })

    res.json(comments)
  } catch (error) {
    console.error(error)
    res.status(500).end()
  }
}

controller.createComment = async function(req, res) {
  try {
    const content = req.body?.content

    if (typeof content !== 'string') {
      return res.status(400).json({
        error: 'O comentário deve ser um texto.'
      })
    }

    if (!content.trim()) {
      return res.status(400).json({
        error: 'O comentário não pode estar vazio.'
      })
    }

    if (content.length > 5000) {
      return res.status(400).json({
        error: 'O comentário não pode ultrapassar 5000 caracteres.'
      })
    }

    const safeContent = content
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')

    await prisma.xssComment.create({
      data: { content: safeContent }
    })

    return res.status(201).end()
  } catch (error) {
    console.error(error)
    return res.status(500).end()
  }
}

export default controller
