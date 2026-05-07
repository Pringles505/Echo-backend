/**
 * Connects mongoose using process.env.MONGO_URI.
 */
async function connectMongo(mongoose) {
  const mongoUri = typeof process.env.MONGO_URI === 'string'
    ? process.env.MONGO_URI.trim()
    : '';
  if (!mongoUri) {
    throw new Error('Missing MongoDB URI. Set MONGO_URI or MONGO_URI_SECRET.');
  }
  await mongoose.connect(mongoUri);
  console.log('Connected to MongoDB');
}

module.exports = { connectMongo };
