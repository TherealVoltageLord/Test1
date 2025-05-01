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
const { body, validationResult } = require('express-validator');

const ENV_VARS = ['JWT_SECRET', 'CATBOX_API_KEY', 'ADMIN_SECRET_KEY', 'CORS_ORIGIN'];
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
  RATE_LIMIT: { windowMs: 15 * 60 * 1000, max: 100 },
  UPLOAD_LIMITS: { fileSize: 25 * 1024 * 1024 },
  PAGINATION_LIMIT: 10,
  ROLES: { USER: 'user', MODERATOR: 'moderator', ADMIN: 'admin' },
  MESSAGE_TYPES: ['text', 'image', 'video', 'post_share'],
  REPORT_TYPES: ['post', 'comment', 'user'],
  REPORT_STATUS: ['pending', 'resolved'],
  REPORT_ACTIONS: ['warn', 'suspend', 'delete_content', 'dismiss']
};

app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGIN.split(','), credentials: true }));
app.use(express.json());
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));
app.use(rateLimit(CONFIG.RATE_LIMIT));
app.use(express.static(path.join(__dirname, 'public')));

const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: CONFIG.UPLOAD_LIMITS.fileSize },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'video/mp4'];
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
  await fs.mkdir(CONFIG.DATA_DIR, { recursive: true });
  await Promise.all(DATA_FILES.map(async file => {
    const filePath = path.join(CONFIG.DATA_DIR, file);
    try { await fs.access(filePath); } catch { await fs.writeFile(filePath, '{}'); }
  }));
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
  const { data } = await axios.post(CONFIG.CATBOX_API, form, { headers: form.getHeaders() });
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
    const users = await readData('users.json');
    const user = users[req.user.id];
    if (!user || !roles.includes(user.role)) return res.status(403).json({ error: 'Forbidden' });
    req.user.role = user.role;
    next();
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

app.post('/api/register', upload.single('profilePic'), [
  body('username').isLength({ min: 3, max: 30 }).matches(/^[a-zA-Z0-9_]+$/),
  body('email').isEmail(),
  body('password').isLength({ min: 8 }),
  body('age').isInt({ min: 13 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { username, email, password, age } = req.body;
    const users = await readData('users.json');

    if (Object.values(users).some(u => u.username === username)) return res.status(409).json({ error: 'Username exists' });
    if (Object.values(users).some(u => u.email === email)) return res.status(409).json({ error: 'Email exists' });

    const userId = uuidv4();
    users[userId] = {
      id: userId,
      username,
      email,
      password: await bcrypt.hash(password, 12),
      age: parseInt(age),
      profilePic: req.file ? await uploadToCatbox(req.file) : null,
      role: CONFIG.ROLES.USER,
      followers: [],
      following: [],
      createdAt: new Date().toISOString(),
      isActive: true
    };

    await writeData('users.json', users);
    const token = jwt.sign({ id: userId, username, role: CONFIG.ROLES.USER }, CONFIG.JWT_SECRET, { expiresIn: '24h' });
    res.status(201).json({ token, user: users[userId] });
  } catch (error) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', [
  body('username').trim().isLength({ min: 3, max: 30 }),
  body('password').isLength({ min: 8 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });

  const { username, password } = req.body;
  const users = await readData('users.json');
  const user = Object.values(users).find(u => u.username === username);

  if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: 'Invalid credentials' });
  if (!user.isActive) return res.status(403).json({ error: 'Account suspended' });

  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, CONFIG.JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, user: (({ password, ...rest }) => rest)(user) });
});

app.get('/api/users/:userId', authenticate, async (req, res) => {
  const users = await readData('users.json');
  const user = users[req.params.userId];
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json((( { password, ...rest }) => rest)(user));
});

app.patch('/api/users/:userId', authenticate, upload.single('profilePic'), [
  body('username').optional().isLength({ min: 3, max: 30 }),
  body('bio').optional(),
  body('website').optional().isURL()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

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
  res.json((( { password, ...rest }) => rest)(user));
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

app.post('/api/posts', authenticate, upload.single('media'), [
  body('caption').optional(),
  body('tags').optional()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    if (!req.file) return res.status(400).json({ error: 'Media required' });
    const mediaUrl = await uploadToCatbox(req.file);
    const postId = uuidv4();
    const posts = await readData('posts.json');

    posts[postId] = {
      id: postId,
      userId: req.user.id,
      mediaUrl,
      caption: req.body.caption || '',
      tags: req.body.tags ? req.body.tags.split(',') : [],
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

app.get('/api/post/:postId', authenticate, async (req, res) => {
  try {
    const [posts, users] = await Promise.all([
      readData('posts.json'),
      readData('users.json')
    ]);
    
    const post = posts[req.params.postId];
    if (!post) return res.status(404).json({ error: 'Post not found' });

    res.json({
      ...post,
      user: users[post.userId],
      meta: {
        title: `${users[post.userId].username}'s Post`,
        description: post.caption,
        image: post.mediaUrl,
        url: `${process.env.CLIENT_URL}/post/${post.id}`
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch post' });
  }
});

app.delete('/api/posts/:postId', authenticate, async (req, res) => {
  try {
    const { postId } = req.params;
    const posts = await readData('posts.json');
    if (posts[postId].userId !== req.user.id) return res.status(403).json({ error: 'Unauthorized' });
    
    delete posts[postId];
    await writeData('posts.json', posts);
    broadcast('post_deleted', { postId });
    res.json({ message: 'Post deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Post deletion failed' });
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
      await createNotification(post.userId, 'like', {
        userId: req.user.id,
        postId,
        username: req.user.username
      });
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

app.post('/api/posts/:postId/comments', authenticate, [
  body('text').trim().isLength({ min: 1, max: 500 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { postId } = req.params;
    const { text } = req.body;
    const [posts, comments] = await Promise.all([
      readData('posts.json'),
      readData('comments.json')
    ]);

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

    await createNotification(posts[postId].userId, 'comment', {
      userId: req.user.id,
      postId,
      commentId,
      username: req.user.username,
      text: text.substring(0, 30) + (text.length > 30 ? '...' : '')
    });

    broadcast('new_comment', comments[commentId]);
    res.status(201).json(comments[commentId]);
  } catch (error) {
    res.status(500).json({ error: 'Comment failed' });
  }
});

app.get('/api/posts/:postId/comments', authenticate, async (req, res) => {
  try {
    const { postId } = req.params;
    const [posts, comments] = await Promise.all([
      readData('posts.json'),
      readData('comments.json')
    ]);

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
    
    res.json({ message: 'Comment deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete comment' });
  }
});

app.post('/api/stories', authenticate, upload.single('media'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Media required' });
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
    const [stories, follows] = await Promise.all([
      readData('stories.json'),
      readData('follows.json')
    ]);
    
    const userFollows = follows[req.user.id] || [];
    const activeStories = Object.values(stories)
      .filter(story => 
        userFollows.includes(story.userId) && 
        new Date(story.expiresAt) > new Date()
      )
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
    
    res.json({ message: 'Story deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete story' });
  }
});

app.post('/api/users/:userId/follow', authenticate, async (req, res) => {
  try {
    const { userId } = req.params;
    if (req.user.id === userId) return res.status(400).json({ error: 'Cannot follow self' });

    const [users, follows] = await Promise.all([
      readData('users.json'),
      readData('follows.json')
    ]);

    if (!users[userId]) return res.status(404).json({ error: 'User not found' });

    if (!follows[req.user.id]) follows[req.user.id] = [];
    if (follows[req.user.id].includes(userId)) {
      return res.status(400).json({ error: 'Already following' });
    }

    follows[req.user.id].push(userId);
    users[userId].followers.push(req.user.id);
    users[req.user.id].following.push(userId);

    await Promise.all([
      writeData('follows.json', follows),
      writeData('users.json', users)
    ]);

    await createNotification(userId, 'follow', {
      userId: req.user.id,
      username: req.user.username
    });

    broadcast('follow_update', {
      followerId: req.user.id,
      followingId: userId,
      action: 'follow'
    });

    res.json({ message: 'Follow successful' });
  } catch (error) {
    res.status(500).json({ error: 'Follow failed' });
  }
});

app.post('/api/users/:userId/unfollow', authenticate, async (req, res) => {
  try {
    const { userId } = req.params;
    const [users, follows] = await Promise.all([
      readData('users.json'),
      readData('follows.json')
    ]);

    if (!follows[req.user.id] || !follows[req.user.id].includes(userId)) {
      return res.status(400).json({ error: 'Not following' });
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

    res.json({ message: 'Unfollow successful' });
  } catch (error) {
    res.status(500).json({ error: 'Unfollow failed' });
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

app.get('/api/notifications', authenticate, async (req, res) => {
  try {
    const notifications = await readData('notifications.json');
    const userNotifications = Object.values(notifications)
      .filter(n => n.userId === req.user.id)
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
      
    res.json(userNotifications);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get notifications' });
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

app.post('/api/report', authenticate, [
  body('type').isIn(CONFIG.REPORT_TYPES),
  body('targetId').isString(),
  body('reason').isLength({ min: 10, max: 500 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { type, targetId, reason } = req.body;
    const reports = await readData('reports.json');
    const users = await readData('users.json');

    let targetExists = false;
    switch (type) {
      case 'user':
        targetExists = !!users[targetId];
        break;
      case 'post':
        const posts = await readData('posts.json');
        targetExists = !!posts[targetId];
        break;
      case 'comment':
        const comments = await readData('comments.json');
        targetExists = !!comments[targetId];
        break;
    }

    if (!targetExists) return res.status(404).json({ error: 'Target not found' });
    if (type === 'user' && targetId === req.user.id) return res.status(400).json({ error: 'Cannot report self' });

    const existingReport = Object.values(reports).find(r => 
      r.type === type && 
      r.targetId === targetId && 
      r.reporterUserId === req.user.id &&
      r.status === 'pending'
    );

    if (existingReport) return res.status(400).json({ error: 'Report already exists' });

    const reportId = uuidv4();
    reports[reportId] = {
      id: reportId,
      type,
      targetId,
      reporterUserId: req.user.id,
      reportedUserId: type === 'user' ? targetId : null,
      reason,
      status: 'pending',
      createdAt: new Date().toISOString(),
      resolvedAt: null,
      resolvedBy: null,
      actionTaken: null
    };

    await writeData('reports.json', reports);

    const moderators = Object.values(users).filter(u => 
      u.role === CONFIG.ROLES.MODERATOR || u.role === CONFIG.ROLES.ADMIN
    );
    
    await Promise.all(moderators.map(mod => 
      createNotification(mod.id, 'new_report', { reportId, type, targetId })
    ));

    res.status(201).json({ message: 'Report submitted', reportId });
  } catch (error) {
    res.status(500).json({ error: 'Report failed' });
  }
});

app.patch('/api/admin/users/:userId/role', authenticate, authorize([CONFIG.ROLES.ADMIN]), [
  body('role').isIn(Object.values(CONFIG.ROLES))
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { userId } = req.params;
    const { role } = req.body;
    const users = await readData('users.json');
    const targetUser = users[userId];
    const requestingAdmin = users[req.user.id];

    if (!targetUser) return res.status(404).json({ error: 'User not found' });
    if (targetUser.role === CONFIG.ROLES.ADMIN && requestingAdmin.id !== targetUser.id) {
      return res.status(403).json({ error: 'Cannot modify other admins' });
    }

    if (targetUser.role === CONFIG.ROLES.ADMIN && role !== CONFIG.ROLES.ADMIN) {
      const adminCount = Object.values(users).filter(u => 
        u.role === CONFIG.ROLES.ADMIN && u.isActive
      ).length;
      if (adminCount <= 1) return res.status(400).json({ error: 'Cannot remove last admin' });
    }

    targetUser.role = role;
    await writeData('users.json', users);
    broadcast('user_updated', (({ password, ...rest }) => rest)(targetUser));
    
    res.json({ message: 'Role updated', user: targetUser });
  } catch (error) {
    res.status(500).json({ error: 'Role update failed' });
  }
});

app.patch('/api/admin/users/:userId/status', authenticate, authorize([CONFIG.ROLES.ADMIN, CONFIG.ROLES.MODERATOR]), [
  body('isActive').isBoolean()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { userId } = req.params;
    const { isActive } = req.body;
    const users = await readData('users.json');
    const targetUser = users[userId];
    const requestingUser = users[req.user.id];

    if (!targetUser) return res.status(404).json({ error: 'User not found' });
    if (targetUser.role === CONFIG.ROLES.ADMIN && requestingUser.role !== CONFIG.ROLES.ADMIN) {
      return res.status(403).json({ error: 'Cannot modify admins' });
    }

    targetUser.isActive = isActive;
    await writeData('users.json', users);
    broadcast('user_updated', (({ password, ...rest }) => rest)(targetUser));
    
    res.json({ message: 'Status updated', user: targetUser });
  } catch (error) {
    res.status(500).json({ error: 'Status update failed' });
  }
});

app.get('/api/admin/users', authenticate, authorize([CONFIG.ROLES.ADMIN, CONFIG.ROLES.MODERATOR]), async (req, res) => {
  try {
    const { page = 1, limit = 20, search = '', role = '' } = req.query;
    const users = await readData('users.json');
    
    let filteredUsers = Object.values(users);
    if (search) {
      const searchTerm = search.toLowerCase();
      filteredUsers = filteredUsers.filter(u =>
        u.username.toLowerCase().includes(searchTerm) ||
        (u.email && u.email.toLowerCase().includes(searchTerm))
      );
    }
    if (role) filteredUsers = filteredUsers.filter(u => u.role === role);

    const startIndex = (page - 1) * limit;
    const paginatedUsers = filteredUsers
      .slice(startIndex, startIndex + limit)
      .map(u => (({ password, ...rest }) => rest)(u));

    res.json({
      users: paginatedUsers,
      total: filteredUsers.length,
      page: parseInt(page),
      totalPages: Math.ceil(filteredUsers.length / limit)
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.post('/api/users/:id/block', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const blocks = await readData('blocks.json');
    
    if (!blocks[req.user.id]) blocks[req.user.id] = [];
    if (blocks[req.user.id].includes(id)) {
      return res.status(400).json({ error: 'Already blocked' });
    }

    blocks[req.user.id].push(id);
    await writeData('blocks.json', blocks);
    
    res.json({ message: 'Block successful' });
  } catch (error) {
    res.status(500).json({ error: 'Block failed' });
  }
});

app.get('/api/users/blocked', authenticate, async (req, res) => {
  try {
    const [blocks, users] = await Promise.all([
      readData('blocks.json'),
      readData('users.json')
    ]);
    
    const blockedIds = blocks[req.user.id] || [];
    const blockedUsers = blockedIds.map(id => {
      const user = users[id];
      return user ? { id: user.id, username: user.username, profilePic: user.profilePic } : null;
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
    
    if (!blocks[req.user.id] || !blocks[req.user.id].includes(id)) {
      return res.status(400).json({ error: 'Not blocked' });
    }

    blocks[req.user.id] = blocks[req.user.id].filter(blockedId => blockedId !== id);
    await writeData('blocks.json', blocks);
    
    res.json({ message: 'Unblock successful' });
  } catch (error) {
    res.status(500).json({ error: 'Unblock failed' });
  }
});

app.post('/api/posts/:id/save', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const saved = await readData('saved.json');
    
    if (!saved[req.user.id]) saved[req.user.id] = [];
    const index = saved[req.user.id].indexOf(id);
    
    if (index === -1) {
      saved[req.user.id].push(id);
    } else {
      saved[req.user.id].splice(index, 1);
    }
    
    await writeData('saved.json', saved);
    res.json({ saved: index === -1 });
  } catch (error) {
    res.status(500).json({ error: 'Save failed' });
  }
});

app.get('/api/saved', authenticate, async (req, res) => {
  try {
    const [saved, posts] = await Promise.all([
      readData('saved.json'),
      readData('posts.json')
    ]);
    
    const savedIds = saved[req.user.id] || [];
    const savedPosts = savedIds.map(id => posts[id]).filter(Boolean);
    
    res.json(savedPosts);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch saved posts' });
  }
});

app.get('/api/health', async (req, res) => {
  const health = { status: 'healthy', timestamp: new Date().toISOString() };
  try {
    const [users, posts, stories] = await Promise.all([
      readData('users.json'),
      readData('posts.json'),
      readData('stories.json')
    ]);
    health.database = {
      users: Object.keys(users).length,
      posts: Object.keys(posts).length,
      stories: Object.keys(stories).length
    };
    res.json(health);
  } catch (error) {
    res.status(500).json({ status: 'unhealthy' });
  }
});

cron.schedule('0 * * * *', async () => {
  const stories = await readData('stories.json');
  const now = new Date();
  Object.keys(stories).forEach(storyId => {
    if (new Date(stories[storyId].expiresAt) < now) {
      delete stories[storyId];
    }
  });
  await writeData('stories.json', stories);
});

async function startServer() {
  await initializeData();
  app.listen(CONFIG.PORT, () => {
    console.log(`Server running on port ${CONFIG.PORT}`);
  });
}

startServer().catch(error => {
  console.error('Server startup failed:', error);
  process.exit(1);
});
