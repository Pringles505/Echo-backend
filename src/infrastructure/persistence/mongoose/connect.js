/**
 * Connects mongoose using process.env.MONGO_URI.
 */
async function connectMongo(mongoose) {
  const mongoUri = process.env.MONGO_URI;
  await mongoose.connect(mongoUri);
  console.log('Connected to MongoDB');
}

module.exports = { connectMongo };
