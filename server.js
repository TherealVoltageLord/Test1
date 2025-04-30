require('dotenv').config();
const fs = require('fs/promises');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const WebSocket = require('ws');
const expressWs = require('express-ws');
const axios = require('axios');
const FormData = require('form-data');
const { v4: uuidv4 } = require('uuid');
const cron = require('node-cron');
const multer = require('multer');
const validator = require('validator');
const { body, validationResult } = require('express-validator');

const ENV_VARS = [
  'JWT_SECRET', 'CATBOX_API_KEY',
  'ADMIN_SECRET_KEY', 'CORS_ORIGIN', 'GOOGLE_OAUTH_URL', 'FB_OAUTH_URL',
  'OAUTH_CLIENT_ID'
];

ENV_VARS.forEach(varName => {
  if (!process.env[varName]) {
    console.error(`Missing required environment variable: ${varName}`);
    process.exit(1);
  }
});

const app = express();
expressWs(app);
const clients = new Set();

const CONFIG = {
  PORT: process.env.PORT || 3000,
  DATA_DIR: process.env.DATA_DIR || './data',
  JWT_SECRET: process.env.JWT_SECRET,
  ADMIN_SECRET_KEY: process.env.ADMIN_SECRET_KEY,
  CATBOX_API: 'https://catbox.moe/user/api.php',
  CATBOX_API_KEY: process.env.CATBOX_API_KEY,
  RATE_LIMIT: {
    windowMs: 15 * 60 * 1000,
    max: 100
  },
  UPLOAD_LIMITS: {
    fileSize: 25 * 1024 * 1024
  },
  PAGINATION_LIMIT: 10,
  ROLES: {
    USER: 'user',
    MODERATOR: 'moderator',
    ADMIN: 'admin'
  },
  MESSAGE_TYPES: ['text', 'image', 'video', 'post_share'],
  REPORT_TYPES: ['post', 'comment', 'user'],
  REPORT_STATUS: ['pending', 'resolved'],
  REPORT_ACTIONS: ['warn', 'suspend', 'delete_content', 'dismiss']
};

app.use(helmet());
app.use(cors({ 
  origin: process.env.CORS_ORIGIN.split(',').map(origin => origin.trim()),
  credentials: true
}));
app.use(express.json());
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));
app.use(rateLimit(CONFIG.RATE_LIMIT));
app.use(express.static(path.join(__dirname, 'public')));

const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: CONFIG.UPLOAD_LIMITS.fileSize },
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      'image/jpeg', 'image/png', 'image/gif', 
      'video/mp4', 'video/quicktime', 'video/x-msvideo'
    ];
    cb(null, allowedTypes.includes(file.mimetype));
  }
});

const DATA_FILES = [
  'users.json', 'posts.json', 'comments.json', 'stories.json',
  'notifications.json', 'follows.json', 'reports.json',
  'conversations.json', 'messages.json', 'tags.json',
  'analytics.json', 'integrations.json', 'security.json',
  'saved.json', 'blocks.json', 'archives.json'
];

async function initializeData() {
  try {
    await fs.mkdir(CONFIG.DATA_DIR, { recursive: true });
    await Promise.all(DATA_FILES.map(async file => {
      const filePath = path.join(CONFIG.DATA_DIR, file);
      try { await fs.access(filePath); } 
      catch { await fs.writeFile(filePath, '{}'); }
    }));
  } catch (error) {
    console.error('Data initialization failed:', error);
    process.exit(1);
  }
}

async function readData(filename) {
  return JSON.parse(await fs.readFile(path.join(CONFIG.DATA_DIR, filename), 'utf8'));
}

async function writeData(filename, data) {
  const tempPath = path.join(CONFIG.DATA_DIR, `${filename}.tmp`);
  await fs.writeFile(tempPath, JSON.stringify(data, null, 2));
  await fs.rename(tempPath, path.join(CONFIG.DATA_DIR, filename));
}

async function uploadToCatbox(file) {
  const form = new FormData();
  form.append('reqtype', 'fileupload');
  form.append('userhash', CONFIG.CATBOX_API_KEY);
  form.append('fileToUpload', file.buffer, {
    filename: `${uuidv4()}${path.extname(file.originalname)}`,
    contentType: file.mimetype
  });

  const { data } = await axios.post(CONFIG.CATBOX_API, form, {
    headers: form.getHeaders(),
    timeout: 15000
  });

  if (!data.startsWith('http')) throw new Error('Catbox upload failed');
  return data;
}

function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Authentication required' });

  jwt.verify(token, CONFIG.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

function authorize(roles = []) {
  return async (req, res, next) => {
    try {
      const users = await readData('users.json');
      const user = users[req.user.id];
      
      if (!user || !roles.includes(user.role)) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      
      req.user.role = user.role;
      next();
    } catch (error) {
      res.status(500).json({ error: 'Authorization failed' });
    }
  };
}

app.ws('/realtime', ws => {
  clients.add(ws);
  ws.on('close', () => clients.delete(ws));
  ws.on('error', err => console.error('WebSocket error:', err));
});

function broadcast(event, data) {
  const message = JSON.stringify({ event, data });
  clients.forEach(client => client.readyState === WebSocket.OPEN && client.send(message));
}

async function createNotification(userId, type, data) {
  const notifications = await readData('notifications.json');
  const notificationId = uuidv4();
  
  notifications[notificationId] = {
    id: notificationId,
    userId,
    type,
    data,
    read: false,
    createdAt: new Date().toISOString()
  };
  
  await writeData('notifications.json', notifications);
  broadcast('new_notification', { userId, notification: notifications[notificationId] });
}

// Authentication Routes
app.post('/api/register',
  upload.single('profilePic'),
  [
    body('username').isLength({ min: 3, max: 30 }).matches(/^[a-zA-Z0-9_]+$/).withMessage('Invalid username format'),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }),
    body('age').isInt({ min: 13 })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    
    try {
      const { username, email, password, age } = req.body;
      const users = await readData('users.json');
      
      // Check existing users
      if (Object.values(users).some(u => u.username === username)) {
        return res.status(409).json({ error: 'Username already exists' });
      }
      if (Object.values(users).some(u => u.email === email)) {
        return res.status(409).json({ error: 'Email already exists' });
      }
      
      // Handle profile picture upload
      let profilePic = null;
      if (req.file) {
        try {
          profilePic = await uploadToCatbox(req.file);
        } catch (uploadError) {
          console.error('Catbox upload failed:', uploadError);
          return res.status(500).json({ error: 'Profile picture upload failed' });
        }
      }
      
      // Create new user
      const userId = uuidv4();
      const hashedPassword = await bcrypt.hash(password, 12);
      
      users[userId] = {
        id: userId,
        username,
        email,
        password: hashedPassword,
        age: parseInt(age),
        profilePic,
        role: CONFIG.ROLES.USER,
        followers: [],
        following: [],
        createdAt: new Date().toISOString(),
        isActive: true
      };
      
      await writeData('users.json', users);
      
      // Generate JWT token
      const token = jwt.sign({
        id: userId,
        username,
        role: CONFIG.ROLES.USER
      }, CONFIG.JWT_SECRET, { expiresIn: '24h' });
      
      res.status(201).json({
        token,
        user: {
          id: userId,
          username,
          email,
          profilePic,
          role: CONFIG.ROLES.USER,
          createdAt: users[userId].createdAt
        }
      });
      
    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).json({ error: 'Registration failed' });
    }
  });

app.post('/api/login',
  [
    body('username')
    .trim()
    .escape()
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be 3-30 characters')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Invalid username format'),
    body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const firstError = errors.array()[0];
      return res.status(400).json({ error: firstError.msg });
    }
    
    try {
      const { username, password } = req.body;
      const users = await readData('users.json');
      const user = Object.values(users).find(u => u.username === username);
      
      if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      
      if (!user.isActive) {
        return res.status(403).json({ error: 'Account suspended' });
      }
      
      const token = jwt.sign({
        id: user.id,
        username: user.username,
        role: user.role
      }, CONFIG.JWT_SECRET, { expiresIn: '24h' });
      
      res.json({
        token,
        user: (({ password, ...rest }) => rest)(user)
      });
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({ error: 'Login failed' });
    }
  });

app.post('/api/forgot-password', 
  [
    body('email').isEmail().normalizeEmail()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const { email } = req.body;
      const users = await readData('users.json');
      const user = Object.values(users).find(u => u.email === email);

      if (!user) return res.status(404).json({ error: 'User not found' });

      const resetToken = jwt.sign({ id: user.id }, CONFIG.JWT_SECRET, { expiresIn: '1h' });
      user.resetToken = resetToken;
      
      await writeData('users.json', users);

      res.json({ message: 'Password reset email sent' });
    } catch (error) {
      res.status(500).json({ error: 'Failed to send password reset' });
    }
});

app.post('/api/reset-password', 
  [
    body('token').notEmpty(),
    body('newPassword').isLength({ min: 8 })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const { token, newPassword } = req.body;
      const users = await readData('users.json');
      
      let userId;
      try {
        const decoded = jwt.verify(token, CONFIG.JWT_SECRET);
        userId = decoded.id;
      } catch (err) {
        return res.status(400).json({ error: 'Invalid or expired token' });
      }

      const user = users[userId];
      if (!user || user.resetToken !== token) {
        return res.status(400).json({ error: 'Invalid token' });
      }

      user.password = await bcrypt.hash(newPassword, 12);
      delete user.resetToken;
      await writeData('users.json', users);

      res.json({ message: 'Password reset successful' });
    } catch (error) {
      res.status(500).json({ error: 'Password reset failed' });
    }
});

app.get('/api/users/:userId', authenticate, async (req, res) => {
  try {
    const { userId } = req.params;
    const users = await readData('users.json');
    const user = users[userId];

    if (!user) return res.status(404).json({ error: 'User not found' });

    const { password, verificationCode, resetToken, ...publicData } = user;
    res.json(publicData);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

app.patch('/api/users/:userId', 
  authenticate,
  upload.single('profilePic'),
  [
    body('username').optional().isLength({ min: 3, max: 30 }).trim().escape(),
    body('bio').optional().trim().escape(),
    body('website').optional().isURL()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const { userId } = req.params;
      if (req.user.id !== userId) return res.status(403).json({ error: 'Unauthorized' });

      const users = await readData('users.json');
      const user = users[userId];

      if (!user) return res.status(404).json({ error: 'User not found' });

      if (req.body.username) user.username = req.body.username;
      if (req.body.bio) user.bio = req.body.bio;
      if (req.body.website) user.website = req.body.website;
      if (req.file) user.profilePic = await uploadToCatbox(req.file);

      await writeData('users.json', users);
      res.json((( { password, verificationCode, resetToken, ...rest }) => rest)(user));
    } catch (error) {
      res.status(500).json({ error: 'Failed to update profile' });
    }
});

app.get('/api/users/:userId/posts', authenticate, async (req, res) => {
  try {
    const { userId } = req.params;
    const { cursor } = req.query;
    const posts = await readData('posts.json');
    
    const userPosts = Object.values(posts)
      .filter(post => post.userId === userId)
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    const startIndex = cursor ? userPosts.findIndex(post => post.id === cursor) + 1 : 0;
    const paginatedPosts = userPosts.slice(startIndex, startIndex + CONFIG.PAGINATION_LIMIT);

    res.json({
      posts: paginatedPosts,
      nextCursor: paginatedPosts.length === CONFIG.PAGINATION_LIMIT 
        ? paginatedPosts[paginatedPosts.length - 1].id 
        : null
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch user posts' });
  }
});

app.get('/api/users/:userId/stories', authenticate, async (req, res) => {
  try {
    const { userId } = req.params;
    const stories = await readData('stories.json');
    
    const userStories = Object.values(stories)
      .filter(story => story.userId === userId && new Date(story.expiresAt) > new Date())
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    res.json(userStories);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch user stories' });
  }
});

// Post Routes
app.post('/api/posts', 
  authenticate,
  upload.single('media'),
  [
    body('caption').optional().trim().escape(),
    body('tags').optional()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const { caption, tags } = req.body;
      if (!req.file) return res.status(400).json({ error: 'Media file is required' });

      const mediaUrl = await uploadToCatbox(req.file);
      const postId = uuidv4();

      const posts = await readData('posts.json');
      posts[postId] = {
        id: postId,
        userId: req.user.id,
        mediaUrl,
        caption: caption || '',
        tags: tags ? tags.split(',').map(tag => tag.trim()) : [],
        likes: [],
        comments: [],
        createdAt: new Date().toISOString()
      };

      await writeData('posts.json', posts);
      broadcast('new_post', posts[postId]);
      res.status(201).json(posts[postId]);
    } catch (error) {
      res.status(500).json({ error: 'Post creation failed' });
    }
});

app.get('/api/posts/:postId', authenticate, async (req, res) => {
  try {
    const { postId } = req.params;
    const posts = await readData('posts.json');
    const post = posts[postId];

    if (!post) return res.status(404).json({ error: 'Post not found' });

    res.json(post);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch post' });
  }
});

app.delete('/api/posts/:postId', authenticate, async (req, res) => {
  try {
    const { postId } = req.params;
    const posts = await readData('posts.json');
    const post = posts[postId];

    if (!post) return res.status(404).json({ error: 'Post not found' });
    if (post.userId !== req.user.id) return res.status(403).json({ error: 'Unauthorized' });

    delete posts[postId];
    await writeData('posts.json', posts);
    broadcast('post_deleted', { postId });
    res.json({ message: 'Post deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete post' });
  }
});

app.get('/api/posts', authenticate, async (req, res) => {
  try {
    const { cursor } = req.query;
    const posts = await readData('posts.json');
    
    const allPosts = Object.values(posts)
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    const startIndex = cursor ? allPosts.findIndex(post => post.id === cursor) + 1 : 0;
    const paginatedPosts = allPosts.slice(startIndex, startIndex + CONFIG.PAGINATION_LIMIT);

    res.json({
      posts: paginatedPosts,
      nextCursor: paginatedPosts.length === CONFIG.PAGINATION_LIMIT 
        ? paginatedPosts[paginatedPosts.length - 1].id 
        : null
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch posts' });
  }
});

// Post Interaction Routes
app.post('/api/posts/:postId/like', authenticate, async (req, res) => {
  try {
    const { postId } = req.params;
    const posts = await readData('posts.json');
    const post = posts[postId];

    if (!post) return res.status(404).json({ error: 'Post not found' });

    const userId = req.user.id;
    const likeIndex = post.likes.indexOf(userId);
    
    if (likeIndex === -1) {
      post.likes.push(userId);
      await createNotification(
        post.userId, 
        'like', 
        { userId: req.user.id, postId, username: req.user.username }
      );
    } else {
      post.likes.splice(likeIndex, 1);
    }

    await writeData('posts.json', posts);
    broadcast('post_updated', post);
    res.json(post);
  } catch (error) {
    res.status(500).json({ error: 'Like operation failed' });
  }
});

app.post('/api/posts/:postId/comments', 
  authenticate,
  [
    body('text').trim().escape().isLength({ min: 1, max: 500 })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const { postId } = req.params;
      const { text } = req.body;
      const posts = await readData('posts.json');
      const comments = await readData('comments.json');

      if (!posts[postId]) return res.status(404).json({ error: 'Post not found' });

      const commentId = uuidv4();
      comments[commentId] = {
        id: commentId,
        postId,
        userId: req.user.id,
        text,
        createdAt: new Date().toISOString()
      };

      posts[postId].comments.push(commentId);
      
      await Promise.all([
        writeData('posts.json', posts),
        writeData('comments.json', comments)
      ]);

      await createNotification(
        posts[postId].userId,
        'comment',
        { 
          userId: req.user.id, 
          postId, 
          commentId,
          username: req.user.username,
          text: text.substring(0, 30) + (text.length > 30 ? '...' : '')
        }
      );

      broadcast('new_comment', comments[commentId]);
      res.status(201).json(comments[commentId]);
    } catch (error) {
      res.status(500).json({ error: 'Comment failed' });
    }
});

app.get('/api/posts/:postId/comments', authenticate, async (req, res) => {
  try {
    const { postId } = req.params;
    const posts = await readData('posts.json');
    const comments = await readData('comments.json');

    if (!posts[postId]) return res.status(404).json({ error: 'Post not found' });

    const postComments = posts[postId].comments
      .map(commentId => comments[commentId])
      .filter(Boolean)
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    res.json(postComments);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch comments' });
  }
});

app.delete('/api/comments/:commentId', authenticate, async (req, res) => {
  try {
    const { commentId } = req.params;
    const comments = await readData('comments.json');
    const comment = comments[commentId];

    if (!comment) return res.status(404).json({ error: 'Comment not found' });
    if (comment.userId !== req.user.id) return res.status(403).json({ error: 'Unauthorized' });

    const posts = await readData('posts.json');
    const post = posts[comment.postId];
    if (post) {
      post.comments = post.comments.filter(id => id !== commentId);
      await writeData('posts.json', posts);
    }

    delete comments[commentId];
    await writeData('comments.json', comments);
    broadcast('comment_deleted', { commentId, postId: comment.postId });
    res.json({ message: 'Comment deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete comment' });
  }
});

// Story Routes
app.post('/api/stories', 
  authenticate,
  upload.single('media'),
  async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ error: 'Media file is required' });

      const mediaUrl = await uploadToCatbox(req.file);
      const storyId = uuidv4();

      const stories = await readData('stories.json');
      stories[storyId] = {
        id: storyId,
        userId: req.user.id,
        mediaUrl,
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
      };

      await writeData('stories.json', stories);
      broadcast('new_story', stories[storyId]);
      res.status(201).json(stories[storyId]);
    } catch (error) {
      res.status(500).json({ error: 'Story creation failed' });
    }
});

app.get('/api/stories', authenticate, async (req, res) => {
  try {
    const stories = await readData('stories.json');
    const follows = await readData('follows.json');
    const userFollows = follows[req.user.id] || [];

    const activeStories = Object.values(stories)
      .filter(story => {
        return userFollows.includes(story.userId) && 
               new Date(story.expiresAt) > new Date();
      })
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    res.json(activeStories);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch stories' });
  }
});

app.delete('/api/stories/:storyId', authenticate, async (req, res) => {
  try {
    const { storyId } = req.params;
    const stories = await readData('stories.json');
    const story = stories[storyId];

    if (!story) return res.status(404).json({ error: 'Story not found' });
    if (story.userId !== req.user.id) return res.status(403).json({ error: 'Unauthorized' });

    delete stories[storyId];
    await writeData('stories.json', stories);
    broadcast('story_deleted', { storyId });
    res.json({ message: 'Story deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete story' });
  }
});

app.get('/api/stories/:id/viewers', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const stories = await readData('stories.json');
    const story = stories[id];
    
    if (!story || story.userId !== req.user.id) {
      return res.status(404).json({ error: 'Story not found' });
    }
    
    res.json({ viewers: story.views || [] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get viewers' });
  }
});

// Follow/Unfollow Routes
app.post('/api/users/:userId/follow', authenticate, async (req, res) => {
  try {
    const { userId } = req.params;
    if (req.user.id === userId) {
      return res.status(400).json({ error: 'Cannot follow yourself' });
    }

    const users = await readData('users.json');
    const follows = await readData('follows.json');

    if (!users[userId]) return res.status(404).json({ error: 'User not found' });

    if (!follows[req.user.id]) follows[req.user.id] = [];
    if (!follows[userId]) follows[userId] = [];

    if (follows[req.user.id].includes(userId)) {
      return res.status(400).json({ error: 'Already following this user' });
    }

    follows[req.user.id].push(userId);
    users[userId].followers.push(req.user.id);
    users[req.user.id].following.push(userId);

    await Promise.all([
      writeData('follows.json', follows),
      writeData('users.json', users)
    ]);

    await createNotification(
      userId,
      'follow',
      { userId: req.user.id, username: req.user.username }
    );

    broadcast('follow_update', { 
      followerId: req.user.id, 
      followingId: userId,
      action: 'follow'
    });

    res.json({ message: 'Successfully followed user' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to follow user' });
  }
});

app.post('/api/users/:userId/unfollow', authenticate, async (req, res) => {
  try {
    const { userId } = req.params;
    const follows = await readData('follows.json');
    const users = await readData('users.json');

    if (!follows[req.user.id] || !follows[req.user.id].includes(userId)) {
      return res.status(400).json({ error: 'Not following this user' });
    }

    follows[req.user.id] = follows[req.user.id].filter(id => id !== userId);
    users[userId].followers = users[userId].followers.filter(id => id !== req.user.id);
    users[req.user.id].following = users[req.user.id].following.filter(id => id !== userId);

    await Promise.all([
      writeData('follows.json', follows),
      writeData('users.json', users)
    ]);

    broadcast('follow_update', { 
      followerId: req.user.id, 
      followingId: userId,
      action: 'unfollow'
    });

    res.json({ message: 'Successfully unfollowed user' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to unfollow user' });
  }
});

app.get('/api/users/:userId/followers', authenticate, async (req, res) => {
  try {
    const { userId } = req.params;
    const users = await readData('users.json');
    const user = users[userId];

    if (!user) return res.status(404).json({ error: 'User not found' });

    const followers = user.followers.map(followerId => {
      const { id, username, profilePic } = users[followerId];
      return { id, username, profilePic };
    });

    res.json(followers);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch followers' });
  }
});

app.get('/api/users/:userId/following', authenticate, async (req, res) => {
  try {
    const { userId } = req.params;
    const users = await readData('users.json');
    const user = users[userId];

    if (!user) return res.status(404).json({ error: 'User not found' });

    const following = user.following.map(followingId => {
      const { id, username, profilePic } = users[followingId];
      return { id, username, profilePic };
    });

    res.json(following);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch following' });
  }
});

// Feed Routes
app.get('/api/feed', authenticate, async (req, res) => {
  try {
    const { cursor } = req.query;
    const follows = await readData('follows.json');
    const posts = await readData('posts.json');
    
    const following = follows[req.user.id] || [];
    const feedPosts = Object.values(posts)
      .filter(post => following.includes(post.userId))
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    const startIndex = cursor ? feedPosts.findIndex(post => post.id === cursor) + 1 : 0;
    const paginatedPosts = feedPosts.slice(startIndex, startIndex + CONFIG.PAGINATION_LIMIT);

    res.json({
      posts: paginatedPosts,
      nextCursor: paginatedPosts.length === CONFIG.PAGINATION_LIMIT 
        ? paginatedPosts[paginatedPosts.length - 1].id 
        : null
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch feed' });
  }
});

// Search Routes
app.get('/api/search', authenticate, async (req, res) => {
  try {
    const { query } = req.query;
    if (!query || query.length < 2) {
      return res.status(400).json({ error: 'Search query must be at least 2 characters' });
    }

    const users = await readData('users.json');
    const posts = await readData('posts.json');

    const searchQuery = query.toLowerCase();

    const userResults = Object.values(users)
      .filter(user => 
        user.username.toLowerCase().includes(searchQuery) ||
        (user.bio && user.bio.toLowerCase().includes(searchQuery))
      )
      .map(user => {
        const { id, username, profilePic, bio } = user;
        return { id, username, profilePic, bio };
      });

    const postResults = Object.values(posts)
      .filter(post => 
        post.caption.toLowerCase().includes(searchQuery) ||
        post.tags.some(tag => tag.toLowerCase().includes(searchQuery))
      )
      .map(post => {
        const { id, userId, mediaUrl, caption, likes, comments, createdAt } = post;
        return { id, userId, mediaUrl, caption, likes, comments, createdAt };
      });

    res.json({
      users: userResults,
      posts: postResults
    });
  } catch (error) {
    res.status(500).json({ error: 'Search failed' });
  }
});

// Notification Routes
app.get('/api/notifications', authenticate, async (req, res) => {
  try {
    const notifications = await readData('notifications.json');
    const userNotifications = Object.values(notifications)
      .filter(notification => notification.userId === req.user.id)
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    res.json(userNotifications);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch notifications' });
  }
});

app.patch('/api/notifications/:notificationId', authenticate, async (req, res) => {
  try {
    const { notificationId } = req.params;
    const notifications = await readData('notifications.json');
    const notification = notifications[notificationId];

    if (!notification) return res.status(404).json({ error: 'Notification not found' });
    if (notification.userId !== req.user.id) return res.status(403).json({ error: 'Unauthorized' });

    notification.read = true;
    await writeData('notifications.json', notifications);
    res.json(notification);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update notification' });
  }
});

// Admin Routes
app.post('/api/admin/users/:userId/role',
  authenticate,
  authorize([CONFIG.ROLES.ADMIN]),
  [
    body('role').isIn([CONFIG.ROLES.USER, CONFIG.ROLES.MODERATOR, CONFIG.ROLES.ADMIN])
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const { userId } = req.params;
      const { role } = req.body;
      const users = await readData('users.json');
      const requestingAdmin = users[req.user.id];
      const targetUser = users[userId];

      if (!targetUser) return res.status(404).json({ error: 'User not found' });
      if (targetUser.role === CONFIG.ROLES.ADMIN && requestingAdmin.id !== targetUser.id) {
        return res.status(403).json({ error: 'Cannot modify other admins' });
      }

      if (targetUser.role === CONFIG.ROLES.ADMIN && role !== CONFIG.ROLES.ADMIN) {
        const adminCount = Object.values(users).filter(u => 
          u.role === CONFIG.ROLES.ADMIN && u.isActive
        ).length;
        
        if (adminCount <= 1) {
          return res.status(400).json({ error: 'Cannot downgrade the last admin' });
        }
      }

      targetUser.role = role;
      await writeData('users.json', users);

      res.json({ 
        message: 'User role updated successfully',
        userId,
        newRole: role
      });
    } catch (error) {
      res.status(500).json({ error: 'Failed to update user role' });
    }
});

app.post('/api/admin/users/:userId/status',
  authenticate,
  authorize([CONFIG.ROLES.ADMIN, CONFIG.ROLES.MODERATOR]),
  [
    body('isActive').isBoolean()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const { userId } = req.params;
      const { isActive } = req.body;
      const users = await readData('users.json');
      const requestingUser = users[req.user.id];
      const targetUser = users[userId];

      if (!targetUser) return res.status(404).json({ error: 'User not found' });
      
      if (requestingUser.role === CONFIG.ROLES.MODERATOR && 
          (targetUser.role === CONFIG.ROLES.ADMIN || targetUser.role === CONFIG.ROLES.MODERATOR)) {
        return res.status(403).json({ error: 'Insufficient privileges' });
      }

      if (requestingUser.id === targetUser.id && !isActive) {
        return res.status(400).json({ error: 'Cannot suspend your own account' });
      }

      if (targetUser.role === CONFIG.ROLES.ADMIN && !isActive) {
        const activeAdminCount = Object.values(users).filter(u => 
          u.role === CONFIG.ROLES.ADMIN && u.isActive
        ).length;
        
        if (activeAdminCount <= 1) {
          return res.status(400).json({ error: 'Cannot suspend the last active admin' });
        }
      }

      targetUser.isActive = isActive;
      await writeData('users.json', users);

      broadcast('user_status_changed', { 
        userId,
        isActive,
        updatedBy: req.user.id
      });

      res.json({ 
        message: `User account ${isActive ? 'activated' : 'suspended'} successfully`,
        userId,
        isActive
      });
    } catch (error) {
      res.status(500).json({ error: 'Failed to update user status' });
    }
});

app.get('/api/admin/users',
  authenticate,
  authorize([CONFIG.ROLES.ADMIN, CONFIG.ROLES.MODERATOR]),
  async (req, res) => {
    try {
      const { page = 1, limit = 20, search = '', role = '' } = req.query;
      const users = await readData('users.json');
      
      let filteredUsers = Object.values(users);

      if (search) {
        const searchTerm = search.toLowerCase();
        filteredUsers = filteredUsers.filter(user => 
          user.username.toLowerCase().includes(searchTerm) ||
          (user.email && user.email.toLowerCase().includes(searchTerm))
        );
      }

      if (role) {
        filteredUsers = filteredUsers.filter(user => user.role === role);
      }

      const startIndex = (page - 1) * limit;
      const endIndex = page * limit;
      const paginatedUsers = filteredUsers.slice(startIndex, endIndex);

      const sanitizedUsers = paginatedUsers.map(user => {
        const { password, verificationCode, resetToken, ...rest } = user;
        return rest;
      });

      res.json({
        users: sanitizedUsers,
        total: filteredUsers.length,
        page: parseInt(page),
        totalPages: Math.ceil(filteredUsers.length / limit)
      });
    } catch (error) {
      res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.delete('/api/admin/users/:userId',
  authenticate,
  authorize([CONFIG.ROLES.ADMIN]),
  async (req, res) => {
    try {
      const { userId } = req.params;
      const users = await readData('users.json');
      const requestingAdmin = users[req.user.id];
      const targetUser = users[userId];

      if (!targetUser) return res.status(404).json({ error: 'User not found' });
      if (targetUser.role === CONFIG.ROLES.ADMIN) {
        return res.status(403).json({ error: 'Cannot delete admin users' });
      }

      const posts = await readData('posts.json');
      const comments = await readData('comments.json');
      const stories = await readData('stories.json');
      const follows = await readData('follows.json');
      const notifications = await readData('notifications.json');
      const reports = await readData('reports.json');

      Object.keys(posts).forEach(postId => {
        if (posts[postId].userId === userId) {
          delete posts[postId];
        }
      });

      Object.keys(comments).forEach(commentId => {
        if (comments[commentId].userId === userId) {
          delete comments[commentId];
        }
      });

      Object.keys(stories).forEach(storyId => {
        if (stories[storyId].userId === userId) {
          delete stories[storyId];
        }
      });

      Object.keys(follows).forEach(followerId => {
        follows[followerId] = follows[followerId].filter(id => id !== userId);
      });
      delete follows[userId];

      Object.keys(notifications).forEach(notificationId => {
        if (notifications[notificationId].userId === userId) {
          delete notifications[notificationId];
        }
      });

      Object.keys(reports).forEach(reportId => {
        if (reports[reportId].reportedUserId === userId) {
          reports[reportId].status = 'user_deleted';
        }
        if (reports[reportId].reporterUserId === userId) {
          reports[reportId].reporterUserId = 'deleted_user';
        }
      });

      delete users[userId];

      await Promise.all([
        writeData('users.json', users),
        writeData('posts.json', posts),
        writeData('comments.json', comments),
        writeData('stories.json', stories),
        writeData('follows.json', follows),
        writeData('notifications.json', notifications),
        writeData('reports.json', reports)
      ]);

      broadcast('user_deleted', { userId, deletedBy: req.user.id });
      res.json({ message: 'User deleted successfully' });
    } catch (error) {
      res.status(500).json({ error: 'Failed to delete user' });
    }
});

// Report Routes
app.post('/api/report',
  authenticate,
  [
    body('type').isIn(CONFIG.REPORT_TYPES),
    body('targetId').isString(),
    body('reason').isString().isLength({ min: 10, max: 500 })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const { type, targetId, reason } = req.body;
      const reports = await readData('reports.json');
      const users = await readData('users.json');
      const reporterId = req.user.id;

      let targetExists = false;
      if (type === 'user') {
        targetExists = !!users[targetId];
      } else if (type === 'post') {
        const posts = await readData('posts.json');
        targetExists = !!posts[targetId];
      } else if (type === 'comment') {
        const comments = await readData('comments.json');
        targetExists = !!comments[targetId];
      }

      if (!targetExists) return res.status(404).json({ error: 'Report target not found' });
      if (type === 'user' && targetId === reporterId) {
        return res.status(400).json({ error: 'Cannot report yourself' });
      }

      const existingReport = Object.values(reports).find(report => 
        report.type === type && 
        report.targetId === targetId && 
        report.reporterUserId === reporterId &&
        report.status === 'pending'
      );

      if (existingReport) {
        return res.status(400).json({ error: 'You already have a pending report for this target' });
      }

      const reportId = uuidv4();
      reports[reportId] = {
        id: reportId,
        type,
        targetId,
        reporterUserId: reporterId,
        reportedUserId: type === 'user' ? targetId : null,
        reason,
        status: 'pending',
        createdAt: new Date().toISOString(),
        resolvedAt: null,
        resolvedBy: null
      };

      await writeData('reports.json', reports);

      const allUsers = await readData('users.json');
      const moderators = Object.values(allUsers).filter(u => 
        u.role === CONFIG.ROLES.ADMIN || u.role === CONFIG.ROLES.MODERATOR
      );

      await Promise.all(moderators.map(moderator => 
        createNotification(
          moderator.id,
          'new_report',
          { reportId, type, targetId }
        )
      ));

      res.status(201).json({ 
        message: 'Report submitted successfully',
        reportId
      });
    } catch (error) {
      res.status(500).json({ error: 'Failed to submit report' });
    }
});

app.get('/api/reports',
  authenticate,
  authorize([CONFIG.ROLES.ADMIN, CONFIG.ROLES.MODERATOR]),
  async (req, res) => {
    try {
      const { status = 'pending', page = 1, limit = 20 } = req.query;
      const reports = await readData('reports.json');
      
      let filteredReports = Object.values(reports);

      if (status) {
        filteredReports = filteredReports.filter(report => report.status === status);
      }

      filteredReports.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

      const startIndex = (page - 1) * limit;
      const endIndex = page * limit;
      const paginatedReports = filteredReports.slice(startIndex, endIndex);

      res.json({
        reports: paginatedReports,
        total: filteredReports.length,
        page: parseInt(page),
        totalPages: Math.ceil(filteredReports.length / limit)
      });
    } catch (error) {
      res.status(500).json({ error: 'Failed to fetch reports' });
    }
});

app.patch('/api/reports/:reportId/resolve',
  authenticate,
  authorize([CONFIG.ROLES.ADMIN, CONFIG.ROLES.MODERATOR]),
  [
    body('action').isIn(CONFIG.REPORT_ACTIONS),
    body('message').optional().isString().isLength({ max: 500 })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const { reportId } = req.params;
      const { action, message } = req.body;
      const reports = await readData('reports.json');
      const users = await readData('users.json');
      const report = reports[reportId];

      if (!report) return res.status(404).json({ error: 'Report not found' });
      if (report.status !== 'pending') {
        return res.status(400).json({ error: 'Report already resolved' });
      }

      const moderator = users[req.user.id];
      let targetUserId = null;
      let notificationData = { reportId, action, message };

      if (report.type === 'user') {
        targetUserId = report.targetId;
      } else if (report.type === 'post') {
        const posts = await readData('posts.json');
        const post = posts[report.targetId];
        if (post) targetUserId = post.userId;
      } else if (report.type === 'comment') {
        const comments = await readData('comments.json');
        const comment = comments[report.targetId];
        if (comment) targetUserId = comment.userId;
      }

      if (targetUserId && action === 'suspend') {
        const targetUser = users[targetUserId];
        if (targetUser) {
          if (moderator.role === CONFIG.ROLES.MODERATOR && 
              (targetUser.role === CONFIG.ROLES.ADMIN || targetUser.role === CONFIG.ROLES.MODERATOR)) {
            return res.status(403).json({ error: 'Insufficient privileges' });
          }

          targetUser.isActive = false;
          notificationData.targetUserId = targetUserId;
        }
      } else if (targetUserId && action === 'warn') {
        notificationData.targetUserId = targetUserId;
      } else if (action === 'delete_content') {
        if (report.type === 'post') {
          const posts = await readData('posts.json');
          delete posts[report.targetId];
          await writeData('posts.json', posts);
          broadcast('post_deleted', { postId: report.targetId, deletedBy: req.user.id });
        } else if (report.type === 'comment') {
          const comments = await readData('comments.json');
          const comment = comments[report.targetId];
          if (comment) {
            const posts = await readData('posts.json');
            const post = posts[comment.postId];
            if (post) {
              post.comments = post.comments.filter(id => id !== report.targetId);
              await writeData('posts.json', posts);
            }
            delete comments[report.targetId];
            await writeData('comments.json', comments);
            broadcast('comment_deleted', { 
              commentId: report.targetId, 
              postId: comment.postId,
              deletedBy: req.user.id
            });
          }
        }
      }

      report.status = 'resolved';
      report.resolvedAt = new Date().toISOString();
      report.resolvedBy = req.user.id;
      report.actionTaken = action;
      report.modMessage = message;

      await Promise.all([
        writeData('reports.json', reports),
        writeData('users.json', users)
      ]);

      if (report.reporterUserId !== 'deleted_user') {
        await createNotification(
          report.reporterUserId,
          'report_resolved',
          notificationData
        );
      }

      if (targetUserId) {
        await createNotification(
          targetUserId,
          'content_action',
          notificationData
        );
      }

      res.json({ 
        message: 'Report resolved successfully',
        reportId,
        actionTaken: action
      });
    } catch (error) {
      res.status(500).json({ error: 'Failed to resolve report' });
    }
});

// Content Saving Routes
app.post('/api/posts/:id/save', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const saved = await readData('saved.json');
    const userId = req.user.id;
    
    if (!saved[userId]) saved[userId] = [];
    const index = saved[userId].indexOf(id);
    
    if (index === -1) {
      saved[userId].push(id);
    } else {
      saved[userId].splice(index, 1);
    }
    
    await writeData('saved.json', saved);
    res.json({ saved: index === -1 });
  } catch (error) {
    res.status(500).json({ error: 'Save operation failed' });
  }
});

app.get('/api/saved', authenticate, async (req, res) => {
  try {
    const saved = await readData('saved.json');
    const posts = await readData('posts.json');
    const userSaved = saved[req.user.id] || [];
    
    const savedPosts = userSaved.map(postId => posts[postId]).filter(Boolean);
    res.json(savedPosts);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch saved posts' });
  }
});

// Block Routes
app.post('/api/users/:id/block', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const blocks = await readData('blocks.json');
    const userId = req.user.id;
    
    if (!blocks[userId]) blocks[userId] = [];
    if (blocks[userId].includes(id)) {
      return res.status(400).json({ error: 'User already blocked' });
    }
    
    blocks[userId].push(id);
    await writeData('blocks.json', blocks);
    res.json({ message: 'User blocked successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Block operation failed' });
  }
});

app.get('/api/users/blocked', authenticate, async (req, res) => {
  try {
    const blocks = await readData('blocks.json');
    const users = await readData('users.json');
    const userBlocks = blocks[req.user.id] || [];
    
    const blockedUsers = userBlocks.map(userId => {
      const { id, username, profilePic } = users[userId];
      return { id, username, profilePic };
    }).filter(Boolean);
    
    res.json(blockedUsers);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch blocked users' });
  }
});

app.post('/api/users/:id/unblock', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const blocks = await readData('blocks.json');
    const userId = req.user.id;
    
    if (!blocks[userId] || !blocks[userId].includes(id)) {
      return res.status(400).json({ error: 'User not blocked' });
    }
    
    blocks[userId] = blocks[userId].filter(blockedId => blockedId !== id);
    await writeData('blocks.json', blocks);
    res.json({ message: 'User unblocked successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Unblock operation failed' });
  }
});

// Archive Routes
app.post('/api/posts/:id/archive', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const archives = await readData('archives.json');
    const userId = req.user.id;
    
    if (!archives[userId]) archives[userId] = [];
    const index = archives[userId].indexOf(id);
    
    if (index === -1) {
      archives[userId].push(id);
    } else {
      archives[userId].splice(index, 1);
    }
    
    await writeData('archives.json', archives);
    res.json({ archived: index === -1 });
  } catch (error) {
    res.status(500).json({ error: 'Archive operation failed' });
  }
});

app.get('/api/archived/posts', authenticate, async (req, res) => {
  try {
    const archives = await readData('archives.json');
    const posts = await readData('posts.json');
    const userArchives = archives[req.user.id] || [];
    
    const archivedPosts = userArchives.map(postId => posts[postId]).filter(Boolean);
    res.json(archivedPosts);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch archived posts' });
  }
});

// Admin Initialization Route
app.post('/api/admin/init', async (req, res) => {
  try {
    const { secretKey, email, password } = req.body;
    
    if (secretKey !== CONFIG.ADMIN_SECRET_KEY) {
      return res.status(401).json({ error: 'Invalid admin secret key' });
    }

    const users = await readData('users.json');
    
    const adminExists = Object.values(users).some(u => u.role === CONFIG.ROLES.ADMIN);
    if (adminExists) {
      return res.status(400).json({ error: 'Admin already initialized' });
    }

    const adminId = uuidv4();
    const adminUsername = 'admin_' + Math.random().toString(36).substring(2, 8);

    users[adminId] = {
      id: adminId,
      username: adminUsername,
      email,
      password: await bcrypt.hash(password, 12),
      role: CONFIG.ROLES.ADMIN,
      verified: true,
      isActive: true,
      createdAt: new Date().toISOString()
    };

    await writeData('users.json', users);

    res.status(201).json({ 
      message: 'Admin account created successfully',
      username: adminUsername
    });
  } catch (error) {
    res.status(500).json({ error: 'Admin initialization failed' });
  }
});

// System Routes
app.get('/api/admin/metrics',
  authenticate,
  authorize([CONFIG.ROLES.ADMIN, CONFIG.ROLES.MODERATOR]),
  async (req, res) => {
    try {
      const users = await readData('users.json');
      const posts = await readData('posts.json');
      const stories = await readData('stories.json');
      const reports = await readData('reports.json');
      const now = new Date();
      const twentyFourHoursAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

      const metrics = {
        totalUsers: Object.keys(users).length,
        activeUsers: Object.values(users).filter(u => u.isActive).length,
        suspendedUsers: Object.values(users).filter(u => !u.isActive).length,
        userRoles: {
          admin: Object.values(users).filter(u => u.role === CONFIG.ROLES.ADMIN).length,
          moderator: Object.values(users).filter(u => u.role === CONFIG.ROLES.MODERATOR).length,
          user: Object.values(users).filter(u => u.role === CONFIG.ROLES.USER).length
        },
        totalPosts: Object.keys(posts).length,
        totalStories: Object.values(stories).filter(
          story => new Date(story.expiresAt) > now
        ).length,
        newUsersLast24h: Object.values(users).filter(
          user => new Date(user.createdAt) > twentyFourHoursAgo
        ).length,
        newPostsLast24h: Object.values(posts).filter(
          post => new Date(post.createdAt) > twentyFourHoursAgo
        ).length,
        reports: {
          pending: Object.values(reports).filter(r => r.status === 'pending').length,
          resolved: Object.values(reports).filter(r => r.status === 'resolved').length
        },
        storage: {
          users: Buffer.byteLength(JSON.stringify(users)),
          posts: Buffer.byteLength(JSON.stringify(posts)),
          stories: Buffer.byteLength(JSON.stringify(stories))
        }
      };

      res.json(metrics);
    } catch (error) {
      res.status(500).json({ error: 'Failed to fetch metrics' });
    }
});

app.post('/api/admin/maintenance',
  authenticate,
  authorize([CONFIG.ROLES.ADMIN]),
  [
    body('action').isIn(['backup', 'cleanup'])
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { action } = req.body;
      
      if (action === 'backup') {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const backupDir = path.join(CONFIG.DATA_DIR, 'backups', timestamp);
        await fs.mkdir(backupDir, { recursive: true });

        await Promise.all(DATA_FILES.map(async file => {
          const source = path.join(CONFIG.DATA_DIR, file);
          const dest = path.join(backupDir, file);
          await fs.copyFile(source, dest);
        }));

        res.json({ 
          message: 'Backup created successfully',
          backupPath: backupDir
        });
      } else if (action === 'cleanup') {
        const stories = await readData('stories.json');
        const now = new Date();
        let expiredCount = 0;

        Object.keys(stories).forEach(storyId => {
          if (new Date(stories[storyId].expiresAt) < now) {
            delete stories[storyId];
            expiredCount++;
          }
        });

        const notifications = await readData('notifications.json');
        const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
        let oldNotificationsCount = 0;

        Object.keys(notifications).forEach(notificationId => {
          if (new Date(notifications[notificationId].createdAt) < thirtyDaysAgo) {
            delete notifications[notificationId];
            oldNotificationsCount++;
          }
        });

        await Promise.all([
          writeData('stories.json', stories),
          writeData('notifications.json', notifications)
        ]);

        res.json({ 
          message: 'Cleanup completed',
          expiredStoriesRemoved: expiredCount,
          oldNotificationsRemoved: oldNotificationsCount
        });
      }
    } catch (error) {
      res.status(500).json({ error: 'Maintenance operation failed' });
    }
});

// OAuth Routes
app.get('/api/oauth/:provider', (req, res) => {
  const providers = {
    google: process.env.GOOGLE_OAUTH_URL,
    facebook: process.env.FB_OAUTH_URL
  };
  
  const url = providers[req.params.provider];
  if (!url) return res.status(400).json({ error: 'Invalid provider' });
  
  res.redirect(`${url}?client_id=${process.env.OAUTH_CLIENT_ID}`);
});

app.get('/api/oauth/:provider/callback', async (req, res) => {
  try {
    const { code } = req.query;
    const { provider } = req.params;
    
    const response = await axios.post(provider === 'google' ? 
      'https://oauth2.googleapis.com/token' : 
      'https://graph.facebook.com/v12.0/oauth/access_token', {
      client_id: process.env.OAUTH_CLIENT_ID,
      client_secret: process.env.OAUTH_CLIENT_SECRET,
      code,
      redirect_uri: `${process.env.API_BASE_URL}/api/oauth/${provider}/callback`,
      grant_type: 'authorization_code'
    });

    const { access_token } = response.data;
    const profileResponse = await axios.get(provider === 'google' ?
      'https://www.googleapis.com/oauth2/v3/userinfo' :
      'https://graph.facebook.com/me?fields=id,name,email,picture', {
      headers: { Authorization: `Bearer ${access_token}` }
    });

    const profile = profileResponse.data;
    const users = await readData('users.json');
    let user = Object.values(users).find(u => u.email === profile.email);

    if (!user) {
      const userId = uuidv4();
      user = {
        id: userId,
        username: profile.name.replace(/\s+/g, '_').toLowerCase(),
        email: profile.email,
        profilePic: provider === 'google' ? profile.picture : profile.picture.data.url,
        verified: true,
        role: CONFIG.ROLES.USER,
        followers: [],
        following: [],
        createdAt: new Date().toISOString(),
        isActive: true
      };
      users[userId] = user;
      await writeData('users.json', users);
    }

    const token = jwt.sign({ 
      id: user.id, 
      username: user.username,
      role: user.role
    }, CONFIG.JWT_SECRET, { expiresIn: '24h' });

    res.redirect(`${process.env.CLIENT_URL}/auth/callback?token=${token}`);
  } catch (error) {
    res.redirect(`${process.env.CLIENT_URL}/auth/error`);
  }
});

app.post('/api/developer/apps',
  authenticate,
  [
    body('name').isString().notEmpty(),
    body('description').optional().isString()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const apps = await readData('integrations.json');
      const appId = uuidv4();
      
      apps[appId] = {
        id: appId,
        name: req.body.name,
        description: req.body.description || '',
        secret: uuidv4(),
        userId: req.user.id,
        createdAt: new Date().toISOString(),
        isActive: true
      };
      
      await writeData('integrations.json', apps);
      res.status(201).json(apps[appId]);
    } catch (error) {
      res.status(500).json({ error: 'App creation failed' });
    }
});

app.get('/api/developer/apps', authenticate, async (req, res) => {
  try {
    const apps = await readData('integrations.json');
    const userApps = Object.values(apps).filter(app => app.userId === req.user.id);
    res.json(userApps);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch apps' });
  }
});

app.delete('/api/developer/apps/:appId', authenticate, async (req, res) => {
  try {
    const { appId } = req.params;
    const apps = await readData('integrations.json');
    const app = apps[appId];

    if (!app) return res.status(404).json({ error: 'App not found' });
    if (app.userId !== req.user.id) return res.status(403).json({ error: 'Unauthorized' });

    delete apps[appId];
    await writeData('integrations.json', apps);
    res.json({ message: 'App deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete app' });
  }
});


// Health Check
app.get('/api/health', (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memoryUsage: process.memoryUsage(),
    database: {
      users: 0,
      posts: 0,
      stories: 0
    }
  };

  Promise.all([
    readData('users.json').then(users => {
      health.database.users = Object.keys(users).length;
    }).catch(() => {
      health.status = 'degraded';
      health.database.users = 'unavailable';
    }),
    readData('posts.json').then(posts => {
      health.database.posts = Object.keys(posts).length;
    }).catch(() => {
      health.status = 'degraded';
      health.database.posts = 'unavailable';
    }),
    readData('stories.json').then(stories => {
      health.database.stories = Object.keys(stories).length;
    }).catch(() => {
      health.status = 'degraded';
      health.database.stories = 'unavailable';
    })
  ]).then(() => {
    res.json(health);
  });
});

// Catch-all route for client-side routing
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});


// Cron Jobs
cron.schedule('0 * * * *', async () => {
  try {
    const stories = await readData('stories.json');
    const now = new Date();
    let expiredCount = 0;

    Object.keys(stories).forEach(storyId => {
      if (new Date(stories[storyId].expiresAt) < now) {
        delete stories[storyId];
        expiredCount++;
      }
    });

    if (expiredCount > 0) {
      await writeData('stories.json', stories);
      console.log(`Cleaned up ${expiredCount} expired stories`);
    }
  } catch (error) {
    console.error('Failed to clean up expired stories:', error);
  }
});

cron.schedule('0 2 * * *', async () => {
  try {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupDir = path.join(CONFIG.DATA_DIR, 'backups', timestamp);
    await fs.mkdir(backupDir, { recursive: true });

    await Promise.all(DATA_FILES.map(async file => {
      const source = path.join(CONFIG.DATA_DIR, file);
      const dest = path.join(backupDir, file);
      await fs.copyFile(source, dest);
    }));

    console.log(`Database backup created at ${backupDir}`);
  } catch (error) {
    console.error('Failed to create database backup:', error);
  }
});

// Initialize server
async function startServer() {
  await initializeData();
  app.listen(CONFIG.PORT, () => {
    console.log(`Server running on port ${CONFIG.PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log('Available roles:', CONFIG.ROLES);
  });
}

startServer().catch(error => {
  console.error('Server startup failed:', error);
  process.exit(1);
});
