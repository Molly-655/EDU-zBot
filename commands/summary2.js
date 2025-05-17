const axios = require("axios");

module.exports = {
  config: {
    name: "summary2",
    aliases: ["wiki2", "summary"],
    version: "1.6",
    author: "Hassan",
    countDown: 5,
    role: 0,
    shortDescription: "Search Wikipedia for a topic",
    longDescription: "Returns a summary and image for a Wikipedia article",
    category: "info",
    guide: {
      en: "{pn} <search term> - fetch Wikipedia summary and image"
    }
  },

  onStart: async function ({ message, args }) {
    try {
      const query = args.join(" ");
      if (!query) {
        return message.reply("⚠️ | Please provide a search term.\nExample: /wikipedia Alan Turing");
      }

      const apiUrl = `https://en.wikipedia.org/api/rest_v1/page/summary/${encodeURIComponent(query)}`;

      // Show searching indicator
      await message.reply("🔍 Searching Wikipedia...");

      const res = await axios.get(apiUrl, {
        headers: {
          "User-Agent": "WikiBot/1.0 (https://your-bot-url.com/)",
          "Accept": "application/json"
        },
        timeout: 10000
      });

      const data = res.data;

      if (data.type === "disambiguation") {
        return message.reply(`❌ | This term refers to multiple topics.\nPlease be more specific.`);
      }

      if (data.title === "Not found" || data.type === "https://mediawiki.org/wiki/HyperSwitch/errors/not_found") {
        return message.reply(`❌ | No article found for "${query}".\n\nTry these suggestions:\n1. Check your spelling\n2. Use more specific terms\n3. Try similar terms`);
      }

      const title = data.title;
      const summary = data.extract || "No summary available for this article.";
      const imageUrl = data.thumbnail?.source;

      // Format the response without "Read more" link
      let replyText = `📚 ${title}\n\n${summary}`;

      if (imageUrl) {
        // Add image URL in a way your HTML can parse
        replyText += `\n\n🖼️ ${imageUrl}`;
      }

      await message.reply(replyText);

    } catch (err) {
      console.error("[Wikipedia Command Error]", err);

      if (err.code === 'ECONNABORTED') {
        await message.reply("⏳ | Wikipedia is taking too long to respond. Please try again later.");
      } else if (err.response?.status === 404) {
        await message.reply("🔍 | No Wikipedia article found for that topic. Try a different search term.");
      } else if (err.response?.status === 429) {
        await message.reply("🔄 | Wikipedia is rate limiting us. Please wait a minute and try again.");
      } else {
        await message.reply("❌ | Failed to fetch from Wikipedia. Please try again with a different search term.");
      }
    }
  },

  onChat: async function ({ message, args }) {
    return this.onStart({ message, args });
  }
};