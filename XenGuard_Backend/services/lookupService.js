import axios from 'axios';
import LookupHistory from '../models/lookupHistory.js';

class LookupService {
  constructor() {
    this.virusTotalApiKey = process.env.VIRUSTOTAL_API_KEY;
  }

  async lookup(query, type) {
    console.log('Starting lookup:', { query, type });
    
    const results = {
      virusTotal: null,
      history: null
    };

    try {
      // Run lookups in parallel
      const [virusTotalResults, historyResults] = await Promise.all([
        this.lookupVirusTotal(query, type),
        this.lookupHistory(query, type)
      ]);

      results.virusTotal = virusTotalResults;
      results.history = historyResults;

      // Save to history if we got any results
      if (virusTotalResults) {
        await this.saveToHistory(query, type, results);
      }

      return results;
    } catch (error) {
      console.error('Lookup failed:', error);
      throw error;
    }
  }

  async lookupVirusTotal(query, type) {
    console.log('Starting VirusTotal lookup:', { query, type });
    
    if (!this.virusTotalApiKey) {
      throw new Error('VirusTotal API key not configured');
    }

    let endpoint;
    switch (type) {
      case 'ip':
        endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${query}`;
        break;
      case 'domain':
        endpoint = `https://www.virustotal.com/api/v3/domains/${query}`;
        break;
      case 'hash':
        endpoint = `https://www.virustotal.com/api/v3/files/${query}`;
        break;
      default:
        throw new Error('Invalid lookup type');
    }

    try {
      console.log('Making VirusTotal API request to:', endpoint);
      const response = await axios.get(endpoint, {
        headers: {
          'x-apikey': this.virusTotalApiKey
        }
      });

      console.log('VirusTotal API response received:', response.status);
      
      if (!response.data || !response.data.data || !response.data.data.attributes) {
        console.error('Unexpected VirusTotal API response format:', response.data);
        throw new Error('Invalid response format from VirusTotal');
      }

      // Process and format the response based on the type
      const data = response.data.data.attributes;
      return {
        positives: data.last_analysis_stats?.malicious || 0,
        total: data.last_analysis_stats?.total || 0,
        scans: Object.entries(data.last_analysis_results || {}).map(([vendor, result]) => ({
          vendor,
          result: result.result || 'clean',
          detected: result.category === 'malicious'
        }))
      };
    } catch (error) {
      console.error('VirusTotal API error:', {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status
      });
      throw new Error(`VirusTotal lookup failed: ${error.message}`);
    }
  }

  async lookupHistory(query, type) {
    // Implementation of lookupHistory method
    // This method is not provided in the original file or the new code block
    // It's assumed to exist as it's called in the lookup method
    throw new Error('lookupHistory method not implemented');
  }

  async saveToHistory(query, type, results) {
    try {
      const sources = [];
      if (results.virusTotal) sources.push('virustotal');

      const historyEntry = new LookupHistory({
        query,
        type,
        sources,
        results: {
          virusTotal: results.virusTotal
        },
        timestamp: new Date()
      });

      await historyEntry.save();
      return historyEntry;
    } catch (error) {
      console.error('Failed to save to history:', error);
      throw error;
    }
  }
}

export default new LookupService();
