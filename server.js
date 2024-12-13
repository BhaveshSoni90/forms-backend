// Required modules
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Joi = require('joi');
require('dotenv').config();

const app = express();

// Middleware
app.use(express.json());
app.use(cors());
app.use(helmet());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
});
app.use(limiter);

// MongoDB connection
const mongooseUri = process.env.MONGO_URI;
mongoose
  .connect(mongooseUri, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error('MongoDB connection error:', err));

// Schemas and Models
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

userSchema.pre('save', async function (next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

userSchema.methods.comparePassword = async function (password) {
  return await bcrypt.compare(password, this.password);
};

const User = mongoose.model('User', userSchema);

const questionSchema = new mongoose.Schema({
  questionText: { type: String, required: true },
  type: { type: String, required: true },
  options: { type: [String], default: [] },
  questionImage: { type: String, default: '' },
});

const formSchema = new mongoose.Schema({
  title: { type: String, required: true },
  headerImage: { type: String },
  questions: { type: [questionSchema], required: true },
});

const Form = mongoose.model('Form', formSchema);

// Validation Schemas
const userValidationSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
});

const formValidationSchema = Joi.object({
  title: Joi.string().required(),
  headerImage: Joi.string().uri().optional(),
  questions: Joi.array()
    .items(
      Joi.object({
        questionText: Joi.string().required(),
        type: Joi.string().required(),
        options: Joi.array().items(Joi.string()).optional(),
        questionImage: Joi.string().uri().optional(),
      })
    )
    .required(),
});

// Routes
app.post('/api/signup', async (req, res, next) => {
  try {
    const { error } = userValidationSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message });

    const { email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: 'Email already in use' });

    const newUser = new User({ email, password });
    await newUser.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    next(err);
  }
});

app.post('/api/login', async (req, res, next) => {
  try {
    const { error } = userValidationSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message });

    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

    res.status(200).json({ message: 'Login successful', user: { id: user._id, email: user.email } });
  } catch (err) {
    next(err);
  }
});

app.get('/api/forms', async (req, res, next) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    const forms = await Form.find()
      .skip((page - 1) * limit)
      .limit(Number(limit));
    const total = await Form.countDocuments();
    res.json({ total, page, forms });
  } catch (err) {
    next(err);
  }
});

app.post('/api/forms', async (req, res, next) => {
  try {
    const { error } = formValidationSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message });

    const form = new Form(req.body);
    await form.save();
    res.status(201).json(form);
  } catch (err) {
    next(err);
  }
});

// Global Error Handling Middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).json({ error: err.message });
});

// Start the Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
