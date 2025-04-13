const express = require('express');
const router = express.Router();
const knex = require('../knex');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

// Clé secrète pour générer les JWT
const JWT_SECRET = process.env.JWT_SECRET || 'secret123';

// POST /api/auth/admin
router.post('/admin', [
  body('username').notEmpty(), // Vérifie que le nom d'utilisateur est non vide
  body('password').notEmpty() 
], async (req, res) => {
  const errors = validationResult(req);  // Vérification des erreurs de validation
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });  
  const { username, password } = req.body;
  const admin = await knex('users').where({ username, role: 'admin' }).first(); 
  if (!admin) return res.status(401).json({ message: 'Admin introuvable' });  
  const match = await bcrypt.compare(password, admin.password);  
  if (!match) return res.status(401).json({ message: 'Invalid' });  

  const token = jwt.sign({ id: admin.id, role: admin.role }, JWT_SECRET);  
  res.json({ token });  
});

// POST /api/auth/login
router.post('/login', [
  body('username').notEmpty(), 
  body('password').notEmpty()  
], async (req, res) => {
  const errors = validationResult(req);  
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });  

  const { username, password } = req.body;
  const user = await knex('users').whereNot('role', 'admin').andWhere({ username }).first();  
  if (!user) return res.status(401).json({ message: 'User introuvable' });  
  const match = await bcrypt.compare(password, user.password);  
  if (!match) return res.status(401).json({ message: 'Invalid' });  
  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET);  
  res.json({ token }); 
});

// POST /api/auth/new -
router.post('/new', [
  body('username').notEmpty(),  
  body('password').isLength({ min: 4 }),  
  body('role').isIn(['user', 'technician'])  
], async (req, res) => {
  const errors = validationResult(req);  
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() }); 

  const authHeader = req.headers.authorization;  
  if (!authHeader) return res.status(401).json({ message: 'Token requis' });  

  const token = authHeader.split(' ')[1]; 
  try {
    const decoded = jwt.verify(token, JWT_SECRET);  // Vérifie la validité du token
    if (decoded.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });  

    const { username, password, role } = req.body;  
    const hashed = await bcrypt.hash(password, 10); 
    await knex('users').insert({ username, password: hashed, role });  // Insère l'utilisateur dans la DB
    res.json({ message: 'User cree' });
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });  // Si le token est invalide, renvoie une erreur
  }
});

module.exports = router;
