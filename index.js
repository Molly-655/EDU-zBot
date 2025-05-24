const express = require('express');
const bodyParser = require('body-parser');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const axios = require('axios');

const app = express();
const port = process.env.PORT || 3000;

// Ensure directories exist
const publicDir = path.join(__dirname, 'public');
const dataDir = path.join(__dirname, 'data');

if (!fs.existsSync(publicDir)) fs.mkdirSync(publicDir);
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);

// Database and token files
const dbFile = path.join(dataDir, 'bot_memory.db');
const tokensFile = path.join(dataDir, 'tokens.json');
const tokenRefreshFile = path.join(dataDir, 'token_refresh.json');

// Initialize files if they don't exist
if (!fs.existsSync(tokensFile)) {
  fs.writeFileSync(tokensFile, JSON.stringify([]), 'utf8');
}

if (!fs.existsSync(tokenRefreshFile)) {
  fs.writeFileSync(tokenRefreshFile, JSON.stringify({}), 'utf8');
}

// Initialize SQLite database
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database(dbFile);

// Create tables if they don't exist
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    message TEXT NOT NULL,
    sender TEXT NOT NULL,
    message_type TEXT DEFAULT 'text',
    metadata TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS user_context (
    user_id TEXT PRIMARY KEY,
    last_interaction DATETIME,
    conversation_state TEXT,
    user_preferences TEXT,
    conversation_history TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS message_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    sender_id TEXT,
    message_type TEXT,
    status TEXT,
    error_message TEXT,
    metadata TEXT
  )`);

  // New table for token management
  db.run(`CREATE TABLE IF NOT EXISTS token_management (
    page_id TEXT PRIMARY KEY,
    last_refresh DATETIME,
    expires_at DATETIME,
    refresh_token TEXT
  )`);
});

// Middleware
app.use(express.static(publicDir));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Enhanced logging
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// Load bots from tokens.json
let bots = [];
try {
  const data = fs.readFileSync(tokensFile, 'utf8');
  bots = JSON.parse(data);
  console.log(`Loaded ${bots.length} bots from tokens.json`);
} catch (err) {
  console.error('Error reading tokens.json:', err);
}

// Load refresh tokens
let tokenRefreshData = {};
try {
  const data = fs.readFileSync(tokenRefreshFile, 'utf8');
  tokenRefreshData = JSON.parse(data);
} catch (err) {
  console.error('Error reading token_refresh.json:', err);
}

// Default bot configuration
const DEFAULT_VERIFY_TOKEN = "Hassan";
const PREFIX = "-"; // Changed from / to -
if (!bots.some(bot => bot.id === "default-bot")) {
  bots.push({
    id: "default-bot",
    verifyToken: DEFAULT_VERIFY_TOKEN,
    pageAccessToken: "DUMMY_TOKEN",
    geminiKey: "DUMMY_KEY"
  });
  saveBots();
}

// Helper functions
function saveBots() {
  return new Promise((resolve, reject) => {
    fs.writeFile(tokensFile, JSON.stringify(bots, null, 2), 'utf8', (err) => {
      if (err) {
        console.error('Error saving bots:', err);
        reject(err);
      } else {
        console.log('Bots saved to tokens.json');
        resolve();
      }
    });
  });
}

function saveTokenRefreshData() {
  return new Promise((resolve, reject) => {
    fs.writeFile(tokenRefreshFile, JSON.stringify(tokenRefreshData, null, 2), 'utf8', (err) => {
      if (err) {
        console.error('Error saving token refresh data:', err);
        reject(err);
      } else {
        console.log('Token refresh data saved');
        resolve();
      }
    });
  });
}

function getCurrentTime() {
  return new Date().toISOString();
}

function splitLongMessage(message, maxLength = 2000) {
  if (message.length <= maxLength) return [message];
  const chunks = [];
  while (message.length > 0) {
    let splitPoint = message.lastIndexOf(' ', maxLength);
    if (splitPoint === -1) splitPoint = maxLength;
    chunks.push(message.substring(0, splitPoint));
    message = message.substring(splitPoint).trim();
  }
  return chunks;
}

// Token Management Functions
async function validateAccessToken(token) {
  try {
    const response = await axios.get(`https://graph.facebook.com/v19.0/me`, {
      params: { access_token: token }
    });
    return !response.data.error;
  } catch (error) {
    console.error('Token validation error:', error.response?.data?.error?.message || error.message);
    return false;
  }
}

async function refreshAccessToken(refreshToken) {
  try {
    if (!process.env.FB_APP_ID || !process.env.FB_APP_SECRET) {
      throw new Error('Facebook App ID and Secret not configured in environment variables');
    }

    const response = await axios.get(`https://graph.facebook.com/v19.0/oauth/access_token`, {
      params: {
        grant_type: 'fb_exchange_token',
        client_id: process.env.FB_APP_ID,
        client_secret: process.env.FB_APP_SECRET,
        fb_exchange_token: refreshToken
      }
    });

    const { access_token, expires_in } = response.data;
    const expiresAt = new Date(Date.now() + expires_in * 1000).toISOString();

    // Update the bot configuration
    bots[0].pageAccessToken = access_token;
    await saveBots();

    // Update refresh data
    tokenRefreshData['default'] = {
      lastRefresh: new Date().toISOString(),
      expiresAt,
      refreshToken: access_token
    };
    await saveTokenRefreshData();

    return access_token;
  } catch (error) {
    console.error('Token refresh failed:', error.response?.data?.error?.message || error.message);
    throw error;
  }
}

// Database operations
function storeMessage(userId, message, sender, messageType = "text", metadata = null) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO conversations (user_id, message, sender, message_type, metadata, timestamp)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [userId, message, sender, messageType, JSON.stringify(metadata), getCurrentTime()],
      function(err) {
        if (err) return reject(err);
        
        db.get(
          `SELECT conversation_history FROM user_context WHERE user_id = ?`,
          [userId],
          (err, row) => {
            if (err) return reject(err);
            
            const history = row?.conversation_history ? JSON.parse(row.conversation_history) : [];
            const role = sender === "user" ? "user" : "assistant";
            
            history.push({
              role,
              content: message,
              type: messageType
            });
            
            const limitedHistory = history.slice(-50);
            
            db.run(
              `INSERT OR REPLACE INTO user_context 
               (user_id, last_interaction, conversation_history)
               VALUES (?, ?, ?)`,
              [userId, getCurrentTime(), JSON.stringify(limitedHistory)],
              (err) => {
                if (err) return reject(err);
                resolve();
              }
            );
          }
        );
      }
    );
  });
}

function getConversationHistory(userId) {
  return new Promise((resolve, reject) => {
    db.get(
      `SELECT conversation_history FROM user_context WHERE user_id = ?`,
      [userId],
      (err, row) => {
        if (err) return reject(err);
        resolve(row?.conversation_history ? JSON.parse(row.conversation_history) : []);
      }
    );
  });
}

function logMessageStatus(senderId, messageType, status, errorMessage = null, metadata = null) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO message_logs 
       (sender_id, message_type, status, error_message, metadata, timestamp)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [senderId, messageType, status, errorMessage, JSON.stringify(metadata), getCurrentTime()],
      (err) => {
        if (err) reject(err);
        else resolve();
      }
    );
  });
}

// API Endpoints
app.post('/set-tokens', async (req, res) => {
  try {
    const { verifyToken, pageAccessToken, geminiKey, refreshToken } = req.body;
    
    if (!verifyToken || !pageAccessToken || !geminiKey) {
      return res.status(400).send("Required fields: verifyToken, pageAccessToken, geminiKey");
    }
    
    // Validate Facebook token
    try {
      const isValid = await validateAccessToken(pageAccessToken);
      if (!isValid) {
        return res.status(400).send("Invalid Page Access Token");
      }
    } catch (error) {
      return res.status(400).send(`Failed to validate Page Access Token: ${error.message}`);
    }
    
    // Update bot configuration
    const bot = {
      id: "default-bot",
      verifyToken,
      pageAccessToken,
      geminiKey,
      createdAt: getCurrentTime()
    };

    bots[0] = bot;
    console.log(`🔄 Bot configuration updated`);

    // Save refresh token if provided
    if (refreshToken) {
      tokenRefreshData['default'] = {
        lastRefresh: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString(), // 60 days
        refreshToken
      };
      await saveTokenRefreshData();
    }

    await saveBots();
    res.send("✅ Bot configuration saved successfully!");
  } catch (error) {
    console.error('Error in /set-tokens:', error);
    res.status(500).send("Internal server error");
  }
});

app.get('/webhook', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  console.log('🔍 Webhook Verification Request:', {
    mode,
    token,
    challenge,
    allVerifyTokens: bots.map(b => b.verifyToken),
    ip: req.ip
  });

  const matchingBot = bots.find(b => b.verifyToken === token);
  
  if (mode === 'subscribe' && matchingBot) {
    console.log(`✅ Webhook verified for bot ${matchingBot.id}`);
    return res.status(200).send(challenge);
  }

  console.error('❌ Webhook verification failed', {
    reason: !mode ? 'Missing hub.mode' : 
            !token ? 'Missing hub.verify_token' :
            !matchingBot ? 'No matching verify token found' : 'Unknown reason',
    receivedToken: token,
    expectedTokens: bots.map(b => b.verifyToken),
    mode
  });

  res.sendStatus(403);
});

// Enhanced sendFacebookMessage with token refresh
async function sendFacebookMessage(recipientId, message, accessToken) {
  try {
    // First validate the token
    const isValid = await validateAccessToken(accessToken);
    
    if (!isValid) {
      console.log('⚠️ Token invalid or expired. Attempting refresh...');
      
      // Check if we have a refresh token
      const refreshInfo = tokenRefreshData['default'];
      if (refreshInfo && refreshInfo.refreshToken) {
        try {
          const newToken = await refreshAccessToken(refreshInfo.refreshToken);
          console.log('🔄 Successfully refreshed access token');
          
          // Retry with new token
          return await sendFacebookMessage(recipientId, message, newToken);
        } catch (refreshError) {
          console.error('❌ Failed to refresh token:', refreshError);
          throw new Error('Access token expired and refresh failed. Please update the token.');
        }
      } else {
        throw new Error('Access token expired and no refresh token available. Please update the token.');
      }
    }
    
    // Process message sending
    const messages = typeof message === 'string' ? splitLongMessage(message) : [message];
    
    for (const msg of messages) {
      const response = await axios.post(
        `https://graph.facebook.com/v19.0/me/messages`,
        {
          recipient: { id: recipientId },
          message: { text: msg }
        },
        {
          params: { access_token: accessToken },
          headers: { 'Content-Type': 'application/json' }
        }
      );
      
      await logMessageStatus(recipientId, 'text', 'success', null, response.data);
      console.log(`📨 Message sent to ${recipientId}`);
    }
    
    return true;
  } catch (error) {
    console.error('❌ Error sending message:', error.response?.data?.error?.message || error.message);
    await logMessageStatus(
      recipientId,
      'text',
      'failed',
      error.response?.data?.error?.message || error.message,
      error.response?.data
    );
    throw error;
  }
}

// Webhook handler with enhanced error handling
app.post('/webhook', async (req, res) => {
  try {
    console.log('📩 Received webhook event:', req.body);
    
    const body = req.body;
    if (body.object !== 'page') {
      console.warn('⚠️ Received non-page object:', body.object);
      return res.sendStatus(404);
    }

    for (const entry of body.entry) {
      const messaging = entry.messaging;
      if (!messaging || !Array.isArray(messaging)) continue;

      for (const event of messaging) {
        const senderId = event.sender?.id;
        const messageText = event.message?.text;
        const attachments = event.message?.attachments || [];

        if (!senderId) continue;

        console.log(`Message from ${senderId}:`, messageText || '[non-text message]');

        // Find bot config
        const bot = bots[0]; // Using single bot configuration
        if (!bot) {
          console.error('No bot config found');
          continue;
        }

        // Only process text messages
        if (messageText) {
          try {
            if (messageText.startsWith(PREFIX)) {
              // Handle command
              const command = messageText.slice(PREFIX.length).trim().split(' ')[0];
              const response = `Command received: ${command}`;
              await sendFacebookMessage(senderId, response, bot.pageAccessToken);
            } else {
              // Handle regular message
              const reply = await generateGeminiReply(messageText, bot.geminiKey);
              console.log('Sending reply:', reply);
              await sendFacebookMessage(senderId, reply, bot.pageAccessToken);
            }
          } catch (error) {
            console.error('Reply failed:', error);
          }
        } else if (attachments.length > 0) {
          // Handle attachments
          const response = "I received your attachment! (Attachment processing would happen here)";
          await sendFacebookMessage(senderId, response, bot.pageAccessToken);
        }
      }
    }
    
    res.status(200).send('EVENT_RECEIVED');
  } catch (error) {
    console.error('Webhook processing error:', error);
    res.status(500).send('Internal server error');
  }
});

async function generateGeminiReply(userText, geminiKey, history = []) {
  try {
    console.log('🧠 Generating Gemini reply...');
    const genAI = new GoogleGenerativeAI(geminiKey);
    const model = genAI.getGenerativeModel({ model: 'gemini-pro' });
    
    let prompt = "Your name is KORA AI. Reply with soft vibes. Here's our conversation so far:\n\n";
    
    history.forEach(msg => {
      prompt += `${msg.role === 'user' ? 'User' : 'KORA AI'}: ${msg.content}\n`;
    });
    
    prompt += `\nUser: ${userText}\nKORA AI:`;
    
    const result = await model.generateContent(prompt);
    const response = await result.response.text();
    
    console.log('✅ Gemini response generated successfully');
    return response;
  } catch (e) {
    console.error("❌ Gemini error:", e);
    return "KORA AI is taking a break. Please try again later.";
  }
}

// Additional API endpoints
app.get('/bots', (req, res) => {
  res.json({
    bots: bots.filter(bot => bot.pageAccessToken !== "DUMMY_TOKEN"),
    defaultVerifyToken: DEFAULT_VERIFY_TOKEN,
    serverTime: getCurrentTime()
  });
});

app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: getCurrentTime(),
    botCount: bots.length
  });
});

app.get('/history', async (req, res) => {
  const userId = req.query.userId;
  const adminCode = req.query.adminCode;
  
  if (!userId) {
    return res.status(400).json({ error: "userId parameter is required" });
  }
  
  if (!adminCode || adminCode !== "ICU14CU") {
    return res.status(403).json({ error: "Invalid admin code" });
  }
  
  try {
    const history = await getConversationHistory(userId);
    res.json({ userId, conversationHistory: history });
  } catch (error) {
    console.error('Error fetching history:', error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Serve HTML interface
app.get('/', (req, res) => {
  res.sendFile(path.join(publicDir, 'index.html'));
});

// Start server with token validation
app.listen(port, () => {
  console.log(`🚀 Server is running at http://localhost:${port}`);
  console.log('🔐 Default verify token:', DEFAULT_VERIFY_TOKEN);
  console.log('🤖 Configured bots:', bots.filter(b => b.pageAccessToken !== "DUMMY_TOKEN").length);
  
  // Validate tokens on startup
  bots.forEach(async (bot) => {
    if (bot.pageAccessToken !== "DUMMY_TOKEN") {
      try {
        const isValid = await validateAccessToken(bot.pageAccessToken);
        console.log(`ℹ️ Token status: ${isValid ? 'Valid' : 'Invalid'}`);
        
        if (!isValid && tokenRefreshData['default']?.refreshToken) {
          console.log(`Attempting to refresh token...`);
          await refreshAccessToken(tokenRefreshData['default'].refreshToken);
        }
      } catch (error) {
        console.error(`Error checking token:`, error.message);
      }
    }
  });
});