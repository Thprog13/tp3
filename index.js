require('dotenv').config();
const express = require('express');
const app = express();
const authRoutes = require('./routes/authRoutes');
const ticketRoutes = require('./routes/ticketRoutes');
const knex = require('./knex');

app.use(express.json());

(async () => {
  if (!(await knex.schema.hasTable('users'))) {
    await knex.schema.createTable('users', (table) => {
      table.increments('id').primary();
      table.string('username').notNullable();
      table.string('password').notNullable();
      table.string('role').notNullable(); 
    });
  }
  if (!(await knex.schema.hasTable('tickets'))) {
    await knex.schema.createTable('tickets', (table) => {
      table.increments('id').primary();
      table.string('title').notNullable();
      table.text('description').notNullable();
      table.enum('status', ['open', 'in progress', 'close']).notNullable();
      table.integer('userId').references('id').inTable('users');
      table.integer('technicianId').nullable().references('id').inTable('users');
      table.date('createdAt').notNullable();
      table.date('closedAt').nullable();
    });
  }
})();

app.use('/api/auth', authRoutes);
app.use('/api', ticketRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
