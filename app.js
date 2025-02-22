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
app.get('/users', async (req, res) => {
  try {
    const users = await User.find()
    res.json(users)
  } catch (error) {
    res.status(500).json({ error: 'Error fetching users' })
  }
})

// Read a Single User
app.get('/users/:id', async (req, res) => {
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
app.put('/users/:id', async (req, res) => {
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
app.delete('/users/:id', async (req, res) => {
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

// Start the server
const PORT = 3000
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`)
})
