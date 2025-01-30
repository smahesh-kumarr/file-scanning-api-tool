import axios from 'axios';
import LookupHistory from '../models/lookupHistory.js';

class LookupService {
  constructor() {
    this.vtApiKey = process.env.VIRUSTOTAL_API_KEY;
    this.shodanApiKey = process.env.SHODAN_API_KEY;
    
    // Validate API keys on initialization
    if (!this.vtApiKey) {
      console.error('VirusTotal API key is not configured');
    }
    if (!this.shodanApiKey) {
      console.error('Shodan API key is not configured');
    }
  }

  async lookupVirusTotal(query, type) {
    console.log('Starting VirusTotal lookup:', { query, type });
    
    if (!this.vtApiKey) {
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
          'x-apikey': this.vtApiKey
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

  async lookupShodan(query, type) {
    console.log('Starting Shodan lookup:', { query, type });
    
    if (!this.shodanApiKey) {
      throw new Error('Shodan API key not configured');
    }

    if (type !== 'ip') {
      console.log('Skipping Shodan lookup for non-IP query');
      return null; // Shodan only supports IP lookups
    }

    try {
      const endpoint = `https://api.shodan.io/shodan/host/${query}?key=${this.shodanApiKey}`;
      console.log('Making Shodan API request');
      
      const response = await axios.get(endpoint);
      console.log('Shodan API response received:', response.status);
      
      if (!response.data) {
        console.error('Unexpected Shodan API response format:', response.data);
        throw new Error('Invalid response format from Shodan');
      }

      return {
        ports: response.data.ports || [],
        services: response.data.data?.map(service => ({
          port: service.port,
          name: service.product || service._shodan?.module || 'unknown'
        })) || [],
        os: response.data.os,
        isp: response.data.isp,
        country: response.data.country_name
      };
    } catch (error) {
      console.error('Shodan API error:', {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status
      });
      throw new Error(`Shodan lookup failed: ${error.message}`);
    }
  }

  async saveLookupHistory(query, type, results, userId) {
    try {
      console.log('Saving lookup history:', { query, type, userId });
      
      const sources = [];
      if (results.virustotal) sources.push('virustotal');
      if (results.shodan) sources.push('shodan');

      const history = new LookupHistory({
        query,
        type,
        results,
        sources,
        user: userId
      });

      await history.save();
      console.log('Lookup history saved successfully');
    } catch (error) {
      console.error('Error saving lookup history:', error);
      throw new Error(`Failed to save lookup history: ${error.message}`);
    }
  }

  async getLookupHistory(query) {
    try {
      console.log('Fetching lookup history for query:', query);
      
      const history = await LookupHistory.find({ query })
        .sort({ timestamp: -1 })
        .limit(5)
        .select('timestamp sources -_id');
      
      console.log('Found lookup history entries:', history.length);
      return history;
    } catch (error) {
      console.error('Error fetching lookup history:', error);
      throw new Error(`Failed to fetch lookup history: ${error.message}`);
    }
  }
}

export default new LookupService();
