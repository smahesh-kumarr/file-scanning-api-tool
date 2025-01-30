import mongoose from 'mongoose';

const lookupHistorySchema = new mongoose.Schema({
  query: {
    type: String,
    required: true,
    index: true
  },
  type: {
    type: String,
    enum: ['ip', 'domain', 'hash'],
    required: true
  },
  results: {
    virustotal: Object,
    shodan: Object
  },
  sources: [{
    type: String,
    enum: ['virustotal', 'shodan']
  }],
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

const LookupHistory = mongoose.model('LookupHistory', lookupHistorySchema);

export default LookupHistory;
