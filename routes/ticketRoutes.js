const express = require('express');
const router = express.Router();
const knex = require('../knex');
const { body, param, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'secret123';

// Fonction pour authentifier les requêtes avec un token JWT
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: 'Token required' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
}

// POST /api/tickets (utilisateur ou technicien)
router.post('/tickets', authenticate, [
  body('title').isString().notEmpty(),
  body('description').isString().notEmpty(),
  body('status').isIn(['open', 'in progress', 'closed']),
  body('userId').isInt({ min: 1 }),
  body('technicianId').optional({ nullable: true }).isInt({ min: 1 }),
  body('createdAt').isISO8601(),
  body('closedAt').optional({ nullable: true }).isISO8601()
], async (req, res) => {
  if (req.user.role === 'admin') return res.status(403).json({ message: 'Admins cannot create tickets' });

  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { title, description, status, userId, technicianId, createdAt, closedAt } = req.body;

  if (closedAt && new Date(closedAt) <= new Date(createdAt)) {
    return res.status(400).json({ message: 'closedAt must be after createdAt' });
  }
  if (closedAt && status !== 'closed') {
    return res.status(400).json({ message: 'Status must be closed if closedAt is defined' });
  }

  try {
    const user = await knex('users').where({ id: userId }).first();
    if (!user || user.role !== 'user') return res.status(400).json({ message: 'Invalid userId' });

    if (technicianId) {
      const tech = await knex('users').where({ id: technicianId }).first();
      if (!tech || tech.role !== 'technician') return res.status(400).json({ message: 'Invalid technicianId' });
    }

    const [ticketId] = await knex('tickets').insert({
      title, description, status, userId,
      technicianId: technicianId || null,
      createdAt,
      closedAt: closedAt || null
    });

    res.status(201).json({ message: 'Ticket created', ticketId });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// GET /api/tickets
router.get('/tickets', authenticate, async (req, res) => {
  try {
    if (req.user.role === 'technician') {
      const tickets = await knex('tickets');
      return res.json(tickets);
    }

    if (req.user.role === 'user') {
      const tickets = await knex('tickets').where({ userId: req.user.id });
      return res.json(tickets);
    }

    res.status(403).json({ message: 'Admins cannot access tickets' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// GET /api/tickets/:id 
router.get('/tickets/:id', authenticate, [
  param('id').isInt({ min: 1 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { id } = req.params;
  try {
    const ticket = await knex('tickets').where({ id }).first();
    if (!ticket) return res.status(404).json({ message: 'Ticket not found' });

    // Validation de l'accès pour l'utilisateur
    if (req.user.role === 'user' && ticket.userId !== req.user.id) {
      return res.status(403).json({ message: 'Forbidden' });
    }

    if (req.user.role === 'admin') {
      return res.status(403).json({ message: 'Admins cannot access ticket details' });
    }

    res.json(ticket);
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// PUT /api/tickets/:id (technicien uniquement)
router.put('/tickets/:id', authenticate, [
  param('id').isInt({ min: 1 }),
  body('status').optional().isIn(['open', 'in progress', 'closed']),
  body('title').optional().isString().notEmpty(),
  body('description').optional().isString().notEmpty(),
  body('technicianId').optional({ nullable: true }).isInt({ min: 1 }),
  body('closedAt').optional({ nullable: true }).isISO8601()
], async (req, res) => {
  if (req.user.role !== 'technician') return res.status(403).json({ message: 'seulemtn technicians peut mettre a jour tickets' });

  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { id } = req.params;
  const updateData = req.body;

  try {
    const ticket = await knex('tickets').where({ id }).first();
    if (!ticket) return res.status(404).json({ message: 'Ticket not found' });

    if (updateData.closedAt && new Date(updateData.closedAt) <= new Date(ticket.createdAt)) {
      return res.status(400).json({ message: 'closedAt must be after createdAt' });
    }

    if (updateData.closedAt && updateData.status !== 'closed') {
      return res.status(400).json({ message: 'Status must be closed if closedAt is provided' });
    }

    await knex('tickets').where({ id }).update(updateData);
    res.json({ message: 'Ticket updated' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// DELETE /api/admin/tickets/:id (admin uniquement)
router.delete('/admin/tickets/:id', authenticate, [
  param('id').isInt({ min: 1 })
], async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'seulemt admins delete tickets' });

  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { id } = req.params;
  try {
    const deleted = await knex('tickets').where({ id }).del();
    if (!deleted) return res.status(404).json({ message: 'Ticket not found' });
    res.json({ message: 'Ticket deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

module.exports = router;
