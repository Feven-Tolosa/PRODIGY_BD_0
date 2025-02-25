// models/user.js (MongoDB)
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')

const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  age: {
    type: Number,
    required: true,
  },
  role: {
    type: String,
    enum: ['user', 'admin', 'owner'],
    default: 'user',
  },
})
// Hash the password before saving
UserSchema.pre('save', async function (next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10)
  }
  next()
})
// Method to compare passwords
UserSchema.methods.comparePassword = async function (password) {
  return await bcrypt.compare(password, this.password)
}

module.exports = mongoose.model('User', UserSchema)
