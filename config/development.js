//import db from './db.js';
const db = require('./db')

module.exports = {
	port: process.env.port,
	db:db.development,
	logger: {
		maxSize: 512000,
		maxFiles: 100
	}
};
