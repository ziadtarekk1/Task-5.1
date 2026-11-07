
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';

// Instructor Portal account.
//
// NOTE (security lab): this model is intentionally insecure. Passwords are
// stored in PLAINTEXT (never do this in real code) so that the NoSQL injection
// lab can demonstrate blind $regex password extraction. The apiKey / private
// contact fields are "trophy" data that filter-injection attacks can leak.
const instructorSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    username: { type: String, required: true, unique: true, trim: true },
    // ⚠️ VULNERABLE (lab): plaintext password, no bcrypt hashing.
    password: { type: String, required: true, select: false },
    department: { type: String },
    role: { type: String, default: 'instructor' }, // 'instructor' | 'superadmin'

    // Sensitive "trophy" fields the directory hides but injection can leak.
    apiKey: { type: String },
    privateEmail: { type: String },
    privatePhone: { type: String }
  },
  { timestamps: true }
);

// Hash the password before saving it
instructorSchema.pre('save', async function () {
  if (!this.isModified('password')) return;

  this.password = await bcrypt.hash(this.password, 12);
});

export const Instructor = mongoose.model('Instructor', instructorSchema);
