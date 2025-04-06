import mongoose from 'mongoose';

const lookupHistorySchema = new mongoose.Schema({
  query: {
    type: String,
    required: true
  },
  type: {
    type: String,
    required: true,
    enum: ['ip', 'domain', 'hash']
  },
  sources: [{
    type: String,
    enum: ['virustotal']
  }],
  results: {
    virusTotal: Object
  },
  timestamp: {
    type: Date,
    default: Date.now
  },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }
});

// Index for efficient querying
lookupHistorySchema.index({ query: 1, timestamp: -1 });

export default mongoose.model('LookupHistory', lookupHistorySchema);
