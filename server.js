const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const app = express();

// Middleware
app.use(express.json());
app.use(cors());

// MongoDB connection (without deprecated options)
mongoose.connect('mongodb+srv://formsapp:formsapp@formsapp.taqqy.mongodb.net/formsAppDb?retryWrites=true&w=majority&appName=FormsApp')
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Define schemas and models

// User Schema (for authentication)
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

// Hash password before saving the user
userSchema.pre('save', async function (next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

// Compare password method for login
userSchema.methods.comparePassword = async function (password) {
  return await bcrypt.compare(password, this.password);
};

// User Model
const User = mongoose.model('User', userSchema);

// Question Schema
const questionSchema = new mongoose.Schema({
  questionText: { type: String, required: true },
  type: { type: String, required: true },  // 'text', 'radio', 'checkbox', etc.
  options: { type: [String], default: [] },  // Options array for 'radio' or 'checkbox'
  questionImage: { type: String, default: '' },  // Optional field for image URL
});

// Form Schema (which includes the questions)
const formSchema = new mongoose.Schema({
  title: { type: String, required: true },
  headerImage: { type: String },
  questions: { type: [questionSchema], required: true },  // Array of questions
});

// Create Form model
const Form = mongoose.model('Form', formSchema);

// Routes

// POST /signup - Register new user
app.post('/api/signup', async (req, res) => {
  const { email, password } = req.body;

  // Check if the email already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(400).json({ error: 'Email already in use' });
  }

  // Create and save the new user
  const newUser = new User({ email, password });
  await newUser.save();
  res.status(201).json({ message: 'User registered successfully' });
});

// POST /login - Authenticate existing user
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  // Check if the user exists
  const user = await User.findOne({ email });
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  // Check if the password matches
  const isMatch = await user.comparePassword(password);
  if (!isMatch) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  // Generate a JWT token
  const token = jwt.sign({ userId: user._id }, 'your-jwt-secret', { expiresIn: '1h' });

  res.status(200).json({ message: 'Login successful', token });
});

// Middleware to authenticate the user using JWT token
const authenticate = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ error: 'Please authenticate.' });
  }

  try {
    const decoded = jwt.verify(token, 'your-jwt-secret');
    req.userId = decoded.userId;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
};

// Get all forms (no need for ID)
app.get('/api/forms', authenticate, async (req, res) => {
  try {
    // Fetch all forms from the database
    const forms = await Form.find();
    res.json(forms);  // Return the array of forms
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Create a new form (protected route)
app.post('/api/forms', authenticate, async (req, res) => {
  try {
    // Ensure the "questions" field is an array
    if (!Array.isArray(req.body.questions)) {
      return res.status(400).json({ error: 'The questions field must be an array.' });
    }

    // Optionally, validate each question in the array to ensure it has the required fields
    req.body.questions.forEach((question, index) => {
      if (!question.questionText || !question.type) {
        return res.status(400).json({ error: `Question at index ${index} is missing required fields.` });
      }
    });

    // Create and save the form
    const form = new Form(req.body);
    await form.save();
    res.status(201).json(form); // Respond with the saved form
  } catch (error) {
    console.error('Error saving form:', error);
    res.status(400).json({ error: error.message });
  }
});

// Start the server
const PORT = 5000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
