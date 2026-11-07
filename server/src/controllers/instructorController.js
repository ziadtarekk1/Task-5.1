
import Joi from 'joi';
import bcrypt from 'bcrypt';
import { Instructor } from '../models/Instructor.js';

// =============================================================================
//  INSTRUCTOR PORTAL CONTROLLER  —  ⚠️ INTENTIONALLY VULNERABLE (security lab)
// =============================================================================
//
// Unlike the review/auth controllers in this project, these handlers do NOT
// validate input with Joi and the app has NO express-mongo-sanitize. They pass
// `req.body` / `req.query` straight into Mongoose. Because Express parses JSON
// bodies and bracket-notation query strings into nested objects, an attacker
// can smuggle MongoDB query operators ($ne, $gt, $regex, $where, ...) into
// what the code treats as plain strings.
//
// This is the bug students must find and fix. Do not "clean this up".
// =============================================================================

// NEW: Validate login inputs
const loginSchema = Joi.object({
  username: Joi.string().trim().required(),
  password: Joi.string().required()
});

// NEW: Allow only legitimate search parameters
const searchSchema = Joi.object({
  name: Joi.string().trim(),
  department: Joi.string().trim(),
  role: Joi.string().trim()
}).unknown(false);

function publicProfile(doc) {
  // A successful login is a "trophy": we deliberately return the sensitive
  // fields so a bypass clearly reveals what it compromised.
  return {
    id: doc._id.toString(),
    name: doc.name,
    username: doc.username,
    department: doc.department,
    role: doc.role
  };
}

// POST /api/instructors/login
export async function loginInstructor(req, res, next) {
  try {
    const { username, password } = req.body;
    if (username === undefined || password === undefined) {
      return res.status(400).json({ message: 'username and password are required' });
    }

    // ⚠️ VULNERABLE (NoSQL injection): `username` and `password` are placed
    // directly into the query. Honest clients send strings, but a crafted body
    // like {"username":{"$ne":null},"password":{"$ne":null}} turns this into a
    // filter that matches any account (authentication bypass). With
    // {"password":{"$regex":"^S"}} the success/failure response becomes an
    // oracle for extracting the stored password one character at a time.

    // NEW: Reject objects, operators and invalid input
    const { error, value } = loginSchema.validate(req.body);

    if (error) {
      return res.status(400).json({
        message: 'Invalid login input'
      });
    }

    const instructor = await Instructor.findOne({
      username: value.username
    }).select('+password');

    if (!instructor) {
      return res.status(401).json({
        message: 'Invalid credentials'
      });
    }

    // NEW: Compare against the stored bcrypt password hash
    const validPassword = await bcrypt.compare(
      value.password,
      instructor.password
    );

    if (!validPassword) {
      return res.status(401).json({
        message: 'Invalid credentials'
      });
    }

    return res.json({
      instructor: publicProfile(instructor)
    });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors
// Public directory. Deliberately limited fields so the contrast with the
// leaky /search endpoint below is obvious.
export async function getDirectory(req, res, next) {
  try {
    const instructors = await Instructor.find()
      .select('name department role')
      .sort({ name: 1 })
      .lean();
    res.json({ instructors });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors/search
export async function searchInstructors(req, res, next) {
  try {
    // ⚠️ VULNERABLE (NoSQL injection): the entire query string is used as the
    // MongoDB filter and full documents (incl. password / apiKey / private
    // contact info) are returned. Examples of what this allows:
    //   ?name=Smith                     -> intended, honest use
    //   ?role[$ne]=instructor           -> operator injection, leaks superadmin
    //   ?username[$regex]=^admin        -> regex enumeration
    //   ?$where=this.password.length>10 -> server-side JavaScript execution

    // NEW: Validate and reject unexpected search parameters
    const { error, value } = searchSchema.validate(req.query);

    if (error) {
  return res.status(200).json({
    count: 0,
    instructors: []
  });
}

    // NEW: Build a safe filter using approved fields only
    const filter = {};

    if (value.name !== undefined) {
      filter.name = value.name;
    }

    if (value.department !== undefined) {
      filter.department = value.department;
    }

    if (value.role !== undefined) {
      filter.role = value.role;
    }

    // NEW: Return only public fields
    const instructors = await Instructor.find(filter)
      .select('name department role')
      .lean();

    res.json({
      count: instructors.length,
      instructors
    });
  } catch (err) {
    next(err);
  }
}
