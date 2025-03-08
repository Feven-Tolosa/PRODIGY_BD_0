const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const authenticate = require('./middleware/authenticate')
const authorize = require('./middleware/authorize')
require('dotenv').config()
const express = require('express')
const connectDB = require('./db') // Import the connectDB function
const User = require('./models/user') // Import the User model
const app = express()

// Connect to MongoDB
connectDB()

// Middleware to parse JSON
app.use(express.json())

// Helper function to validate email format
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return emailRegex.test(email)
}

// Create a User
app.post('/users', async (req, res) => {
  const { name, email, age } = req.body

  if (!name || !email || !age) {
    return res.status(400).json({ error: 'Missing fields' })
  }

  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email' })
  }

  try {
    const user = new User({ name, email, age })
    await user.save()
    res.status(201).json(user)
  } catch (error) {
    res.status(500).json({ error: 'Error creating user' })
  }
})

// Read All Users
app.get('/users', authenticate, async (req, res) => {
  try {
    const users = await User.find()
    res.json(users)
  } catch (error) {
    res.status(500).json({ error: 'Error fetching users' })
  }
})

// Read a Single User
app.get('/users/:id', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
    if (!user) {
      return res.status(404).json({ error: 'User not found' })
    }
    res.json(user)
  } catch (error) {
    res.status(500).json({ error: 'Error fetching user' })
  }
})

// Update a User
app.put('/users/:id', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
    if (!user) {
      return res.status(404).json({ error: 'User not found' })
    }

    const { name, email, age } = req.body

    if (email && !isValidEmail(email)) {
      return res.status(400).json({ error: 'Invalid email' })
    }

    user.name = name || user.name
    user.email = email || user.email
    user.age = age || user.age

    await user.save()
    res.json(user)
  } catch (error) {
    res.status(500).json({ error: 'Error updating user' })
  }
})

// Delete a User
app.delete('/users/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params

    // Delete the user
    const result = await User.deleteOne({ _id: id })

    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'User not found' })
    }

    res.sendStatus(204)
  } catch (error) {
    console.error('Error deleting user:', error)
    res.status(500).json({ error: 'Error deleting user' })
  }
})

app.post('/register', async (req, res) => {
  const { name, email, password, age, role } = req.body

  if (!name || !email || !password || !age) {
    return res.status(400).json({ error: 'Missing fields' })
  }

  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email' })
  }

  try {
    const user = new User({ name, email, password, age, role: role || 'user' })
    await user.save()
    res.status(201).json({ message: 'User registered successfully' })
  } catch (error) {
    res.status(500).json({ error: 'Error registering user' })
  }
})

app.post('/login', async (req, res) => {
  const { email, password } = req.body

  if (!email || !password) {
    return res.status(400).json({ error: 'Missing fields' })
  }

  try {
    const user = await User.findOne({ email })

    if (!user) {
      return res.status(404).json({ error: 'User not found' })
    }

    const isPasswordValid = await user.comparePassword(password)

    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid password' })
    }

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    )

    res.json({ token })
  } catch (error) {
    res.status(500).json({ error: 'Error logging in' })
  }
})

// Read All Users (Protected Route)
app.get('/users', authenticate, async (req, res) => {
  try {
    const users = await User.find()
    res.json(users)
  } catch (error) {
    res.status(500).json({ error: 'Error fetching users' })
  }
})

// Read a Single User (Protected Route)
app.get('/users/:id', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
    if (!user) {
      return res.status(404).json({ error: 'User not found' })
    }
    res.json(user)
  } catch (error) {
    res.status(500).json({ error: 'Error fetching user' })
  }
})

// Update a User (Protected Route)
app.put('/users/:id', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
    if (!user) {
      return res.status(404).json({ error: 'User not found' })
    }

    const { name, email, age } = req.body

    if (email && !isValidEmail(email)) {
      return res.status(400).json({ error: 'Invalid email' })
    }

    user.name = name || user.name
    user.email = email || user.email
    user.age = age || user.age

    await user.save()
    res.json(user)
  } catch (error) {
    res.status(500).json({ error: 'Error updating user' })
  }
})

// Delete a User (Protected Route)
app.delete('/users/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params

    const result = await User.deleteOne({ _id: id })

    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'User not found' })
    }

    res.sendStatus(204)
  } catch (error) {
    console.error('Error deleting user:', error)
    res.status(500).json({ error: 'Error deleting user' })
  }
})

// Protected Route for Admins Only
app.get('/admin', authenticate, authorize(['admin']), (req, res) => {
  res.json({ message: 'Welcome, admin' })
})

// Protected Route for Owners Only
app.get('/owner', authenticate, authorize(['owner']), (req, res) => {
  res.json({ message: 'Welcome, owner' })
})
// Start the server
const PORT = 3000
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`)
})
