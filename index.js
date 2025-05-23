const express = require('express');
const bodyParser = require('body-parser');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { GoogleGenerativeAI } = require('@google/generative-ai');

const app = express();
const port = process.env.PORT || 3000;

// Ensure public directory exists
const publicDir = path.join(__dirname, 'public');
if (!fs.existsSync(publicDir)) {
  fs.mkdirSync(publicDir);
}

// Create tokens.json if it doesn't exist
const tokensFile = path.join(__dirname, 'tokens.json');
if (!fs.existsSync(tokensFile)) {
  fs.writeFileSync(tokensFile, JSON.stringify([]), 'utf8');
}

// Serve static files from public
app.use(express.static(publicDir));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Enhanced logging middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

let bots = [];

// Load existing bots from tokens.json
try {
  const data = fs.readFileSync(tokensFile, 'utf8');
  bots = JSON.parse(data);
  console.log(`Loaded ${bots.length} bots from tokens.json`);
} catch (err) {
  console.error('Error reading tokens.json:', err);
}

// TEMP: Hardcoded bot so Facebook can verify the webhook
const DEFAULT_VERIFY_TOKEN = "Hassan";
if (!bots.some(bot => bot.id === "default-bot")) {
  bots.push({
    id: "default-bot",
    verifyToken: DEFAULT_VERIFY_TOKEN,
    pageAccessToken: "DUMMY_TOKEN",
    geminiKey: "DUMMY_KEY"
  });
  saveBots(); // Save the default bot
}

// Save bots to tokens.json
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

// Endpoint to set up new bots
app.post('/set-tokens', async (req, res) => {
  try {
    const { verifyToken, pageAccessToken, geminiKey, pageId } = req.body;
    
    if (!verifyToken || !pageAccessToken || !geminiKey || !pageId) {
      return res.status(400).send("All fields are required");
    }
    
    // Check if bot with this pageId already exists
    const existingBotIndex = bots.findIndex(bot => bot.pageId === pageId);
    
    const bot = {
      id: `bot_${Date.now()}`,
      pageId,
      verifyToken,
      pageAccessToken,
      geminiKey,
      createdAt: new Date().toISOString()
    };

    if (existingBotIndex >= 0) {
      bots[existingBotIndex] = bot;
      console.log(`🔄 Bot ${bot.id} updated for page ${pageId}`);
    } else {
      bots.push(bot);
      console.log(`✅ Bot ${bot.id} registered for page ${pageId}`);
    }

    await saveBots();
    res.send("✅ Bot configuration saved successfully!");
  } catch (error) {
    console.error('Error in /set-tokens:', error);
    res.status(500).send("Internal server error");
  }
});

// Add DELETE endpoint for bots
app.delete('/delete-bot/:id', async (req, res) => {
  try {
    const botId = req.params.id;
    const initialLength = bots.length;
    
    bots = bots.filter(bot => bot.id !== botId);
    
    if (bots.length < initialLength) {
      await saveBots();
      console.log(`🗑️ Bot ${botId} deleted`);
      res.sendStatus(200);
    } else {
      res.status(404).send('Bot not found');
    }
  } catch (error) {
    console.error('Error deleting bot:', error);
    res.status(500).send('Internal server error');
  }
});

// Webhook verification endpoint
app.get('/webhook', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  console.log(`Webhook verification attempt with token: ${token}`);
  
  const bot = bots.find(b => b.verifyToken === token);
  if (mode === 'subscribe' && bot) {
    console.log(`✅ Webhook verified for bot ${bot.id}`);
    res.status(200).send(challenge);
  } else {
    console.warn(`❌ Webhook verification failed. Token: ${token}, Mode: ${mode}`);
    res.sendStatus(403);
  }
});

// Handle messages
app.post('/webhook', async (req, res) => {
  try {
    console.log('Received webhook event:', JSON.stringify(req.body, null, 2));
    
    const body = req.body;

    if (body.object === 'page') {
      for (const entry of body.entry) {
        if (!entry.messaging || entry.messaging.length === 0) continue;
        
        const webhookEvent = entry.messaging[0];
        const senderId = webhookEvent.sender.id;
        const pageId = entry.id;  

        console.log(`Processing message from sender ${senderId} on page ${pageId}`);
        
        const bot = bots.find(b => b.pageAccessToken !== "DUMMY_TOKEN" && b.pageId === pageId);  

        if (!bot) {  
          console.warn(`❌ No bot found for page ID: ${pageId}`);  
          continue;
        }  

        if (webhookEvent.message?.text) {  
          console.log(`Received message: "${webhookEvent.message.text}"`);
          try {
            const reply = await generateGeminiReply(webhookEvent.message.text, bot.geminiKey);  
            console.log(`Sending reply: "${reply}"`);
            await sendMessage(senderId, reply, bot.pageAccessToken);  
          } catch (error) {
            console.error('Error processing message:', error);
          }
        }  
      }  
      res.status(200).send('EVENT_RECEIVED');
    } else {
      console.warn('Received unknown webhook object type:', body.object);
      res.sendStatus(404);
    }
  } catch (error) {
    console.error('Error in webhook handler:', error);
    res.status(500).send('Internal server error');
  }
});

// Generate Gemini AI reply
async function generateGeminiReply(userText, geminiKey) {
  try {
    console.log('Generating Gemini reply...');
    const genAI = new GoogleGenerativeAI(geminiKey);
    const model = genAI.getGenerativeModel({ model: 'gemini-pro' });
    const result = await model.generateContent(`Your name is KORA AI. Reply with soft vibes:\n\nUser: ${userText}`);
    const response = await result.response.text();
    console.log('Gemini response generated successfully');
    return response;
  } catch (e) {
    console.error("Gemini error:", e);
    return "KORA AI is taking a break. Please try again later.";
  }
}

// Send reply to Messenger
function sendMessage(recipientId, text, accessToken) {
  return new Promise((resolve, reject) => {
    const body = {
      recipient: { id: recipientId },
      message: { text }
    };

    const request = https.request({
      hostname: 'graph.facebook.com',
      path: `/v12.0/me/messages?access_token=${accessToken}`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });

    request.on('response', (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => {
        console.log(`Facebook API response: ${res.statusCode}`, data);
        resolve(data);
      });
    });

    request.on('error', err => {
      console.error("Send error:", err);
      reject(err);
    });
    
    request.write(JSON.stringify(body));
    request.end();
  });
}

// Endpoint to list all bots (for debugging)
app.get('/bots', (req, res) => {
  res.json(bots.filter(bot => bot.pageAccessToken !== "DUMMY_TOKEN"));
});

// Serve the HTML file
app.get('/', (req, res) => {
  res.sendFile(path.join(publicDir, 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).send('Something broke!');
});

app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});